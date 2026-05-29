-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.ProxySpec
  ( spec
  ) where

import Control.Concurrent              (forkIO)
import Control.Concurrent.Async        (withAsync)
import Control.Concurrent.MVar         (newEmptyMVar, putMVar, takeMVar)
import Control.Exception
    (AsyncException(..), IOException, SomeException, bracket, bracketOnError, finally, throwIO, try)
import Control.Monad                   (unless)
import Data.ByteString                 qualified as BS
import Data.ByteString.Base64          qualified as B64
import Data.ByteString.Char8           qualified as BS8
import Data.ByteString.Lazy            qualified as LBS
import Data.ByteString.Lazy.Char8      qualified as LBS8
import Data.CaseInsensitive            qualified as CI
import Data.IORef
import Data.Maybe                      (fromMaybe, mapMaybe)
import Data.Streaming.Network          qualified as CN
import Data.Streaming.Network.Internal (AppData(..))
import Network.HTTP.Client             qualified as HC
import Network.HTTP.Types              qualified as HT
import Network.HTTP.Types.Header       qualified as HT
import Network.Socket
import Network.Socket.ByteString       qualified as SocketBS
import Network.Wai
import Network.Wai.Internal            (Response(..), ResponseReceived(..))
import Network.Wai.Test
import System.Log.FastLogger           qualified as FL
import System.Timeout                  (timeout)

import Network.HProx.Impl

import Test.Hspec

spec :: Spec
spec = do
    describe "HTTP proxy auth decisions" $ do
        it "challenges unauthorized HTTP proxy requests" $ do
            response <- runProxyApp (httpProxy authRequiredSettings) rawProxyRequest
            simpleStatus response `shouldBe` HT.status407
            lookup "Proxy-Authenticate" (simpleHeaders response) `shouldBe` Just "Basic realm=\"hprox\""

        it "accepts valid Basic credentials" $
            withRawHttpServer (const "ok") $ \port -> do
                response <- runProxyApp (httpProxy authorizedSettings) (proxyRequestForPort port basicAliceSecret)
                simpleStatus response `shouldBe` HT.status200

        it "rejects valid Basic credentials with the wrong password" $ do
            response <- runProxyApp (httpProxy authorizedSettings) (rawProxyRequestWithAuth $ basicCredential "alice:wrong")
            simpleStatus response `shouldBe` HT.status407

        it "rejects malformed base64 credentials even if lenient decoding would authenticate" $ do
            response <- runProxyApp (httpProxy authorizedSettings) (rawProxyRequestWithAuth "Basic !!!YWxpY2U6c2VjcmV0!!!")
            simpleStatus response `shouldBe` HT.status407

        it "rejects non-Basic credentials even when the payload is otherwise valid" $ do
            response <- runProxyApp (httpProxy authorizedSettings) (rawProxyRequestWithAuth $ "Bearer " <> B64.encode "alice:secret")
            simpleStatus response `shouldBe` HT.status407

        it "redacts proxy auth passwords in trace logs" $
            withRawHttpServer (const "ok") $ \port -> do
                logs <- newIORef []
                let loggingSettings = authorizedSettings
                            { logger = \_ msg -> modifyIORef' logs (LBS.fromStrict (FL.fromLogStr msg) :)
                            }
                response <- runProxyApp (httpProxy loggingSettings) (proxyRequestForPort port basicAliceSecret)
                simpleStatus response `shouldBe` HT.status200
                renderedLogs <- LBS.toStrict . LBS.concat . reverse <$> readIORef logs
                renderedLogs `shouldSatisfy` BS8.isInfixOf "authorized request"
                renderedLogs `shouldSatisfy` BS8.isInfixOf "alice:<redacted>"
                renderedLogs `shouldNotSatisfy` BS8.isInfixOf "secret"
                renderedLogs `shouldNotSatisfy` BS8.isInfixOf "alice:secret"

        it "falls back instead of challenging when hidden auth is enabled" $ do
            response <- runProxyApp (httpProxy hiddenAuthSettings) rawProxyRequest
            simpleStatus response `shouldBe` fallbackStatus
            simpleBody response `shouldBe` fallbackBody

    describe "CONNECT proxy auth decisions" $ do
        it "challenges unauthorized CONNECT requests" $ do
            response <- runConnectApp authRequiredSettings connectRequest
            simpleStatus response `shouldBe` HT.status407
            lookup "Proxy-Authenticate" (simpleHeaders response) `shouldBe` Just "Basic realm=\"hprox\""

        it "falls back instead of challenging CONNECT requests when hidden auth is enabled" $ do
            response <- runConnectApp hiddenAuthSettings connectRequest
            simpleStatus response `shouldBe` fallbackStatus
            simpleBody response `shouldBe` fallbackBody

        it "establishes an HTTP/1 CONNECT tunnel after upstream connection succeeds" $ do
            response <- rawConnectRoundTrip
            response `shouldBe` "ping"

        it "returns 502 when upstream CONNECT fails before tunnel establishment" $ do
            port <- getFreePort
            response <- runConnectApp authorizedSettings (connectRequestFor "127.0.0.1" port HT.http11)
            simpleStatus response `shouldBe` HT.status502

        it "returns 502 for HTTP/2 CONNECT when upstream connection fails" $ do
            port <- getFreePort
            response <- runConnectApp authorizedSettings (connectRequestFor "127.0.0.1" port HT.http20)
            simpleStatus response `shouldBe` HT.status502

        it "does not log upstream failure after an HTTP/2 tunnel response starts" $
            withTcpEchoServer $ \targetPort -> do
                logs <- newIORef []
                let loggingSettings = authorizedSettings
                            { logger = \_ msg -> modifyIORef' logs (LBS.fromStrict (FL.fromLogStr msg) :)
                            }
                    tunnelRequest      = connectRequestFor "127.0.0.1" targetPort HT.http20
                    failAfterResponse _ = ioError (userError "client stream closed after connect")
                result <- try (httpConnectProxy loggingSettings fallback tunnelRequest failAfterResponse) :: IO (Either SomeException ResponseReceived)
                case result of
                    Left _  -> return ()
                    Right _ -> expectationFailure "response failure was swallowed"
                renderedLogs <- LBS.toStrict . LBS.concat . reverse <$> readIORef logs
                renderedLogs `shouldNotSatisfy` BS8.isInfixOf "CONNECT upstream failure"

        it "does not log upstream failure when HTTP/2 cancels before the tunnel response starts" $ do
            logs <- newIORef []
            let loggingSettings = authorizedSettings
                        { logger = \_ msg -> modifyIORef' logs (LBS.fromStrict (FL.fromLogStr msg) :)
                        }
                cancelledBeforeResponse _ _ = throwIO ThreadKilled
                respondOk _                 = ioError (userError "respond should not be called")
            result <- try (httpConnectProxyWith cancelledBeforeResponse loggingSettings fallback (connectRequestFor "127.0.0.1" 443 HT.http20) respondOk) :: IO (Either SomeException ResponseReceived)
            case result of
                Left _  -> return ()
                Right _ -> expectationFailure "pre-response cancellation was swallowed"
            renderedLogs <- LBS.toStrict . LBS.concat . reverse <$> readIORef logs
            renderedLogs `shouldNotSatisfy` BS8.isInfixOf "CONNECT upstream failure"

    describe "HTTP proxy fallback decisions" $
        it "falls through for non-proxy GET requests" $ do
            response <- runProxyApp (httpProxy authRequiredSettings) defaultRequest
            simpleStatus response `shouldBe` fallbackStatus
            simpleBody response `shouldBe` fallbackBody

    describe "HTTP proxy target parsing" $ do
        it "selects raw absolute-URI proxy targets with default ports" $
            selectHttpProxyTarget rawProxyRequest
                `shouldBe` Just HttpProxyTarget
                    { httpProxyTargetHost = "example.com"
                    , httpProxyTargetPort = 80
                    , httpProxyTargetRawPath = "/resource"
                    }

        it "preserves bracketed IPv6 proxy targets without explicit ports" $
            selectHttpProxyTarget rawProxyRequest { rawPathInfo = "http://[::1]/resource" }
                `shouldBe` Just HttpProxyTarget
                    { httpProxyTargetHost = "[::1]"
                    , httpProxyTargetPort = 80
                    , httpProxyTargetRawPath = "/resource"
                    }

        it "treats HTTP/2 proxy scheme values case-insensitively" $
            selectHttpProxyTarget http2ProxyRequest { requestHeaders = [("X-Scheme", "HTTP")] }
                `shouldBe` Just HttpProxyTarget
                    { httpProxyTargetHost = "example.com"
                    , httpProxyTargetPort = 80
                    , httpProxyTargetRawPath = "/resource"
                    }

        it "rejects malformed explicit ports in raw absolute-URI requests" $
            selectHttpProxyTarget rawProxyRequest { rawPathInfo = "http://example.com:not-a-port/resource" }
                `shouldBe` Nothing

        it "rejects malformed explicit ports in Host-header proxy requests" $
            selectHttpProxyTarget hostHeaderProxyRequest { requestHeaderHost = Just "example.com:not-a-port" }
                `shouldBe` Nothing

        it "rejects HTTP/2 proxy requests without a Host header" $
            selectHttpProxyTarget http2ProxyRequest { requestHeaderHost = Nothing }
                `shouldBe` Nothing

        it "renders HTTP proxy authorities without the default port" $ do
            renderHttpProxyAuthority (HttpProxyTarget "example.com" 80 "/")
                `shouldBe` "example.com"
            renderHttpProxyAuthority (HttpProxyTarget "example.com" 443 "/")
                `shouldBe` "example.com:443"
            renderHttpProxyAuthority (HttpProxyTarget "example.com" 8080 "/")
                `shouldBe` "example.com:8080"

    describe "HTTP proxy upstream requests" $
        it "uses absolute URI authority for Host and strips proxy boundary headers" $
            withRawHttpServer observeRawProxyRequestBody $ \port -> do
                let authority = "127.0.0.1:" <> BS8.pack (show port)
                    responseBody = LBS8.lines . simpleBody
                    proxiedReq =
                        defaultRequest
                            { requestMethod     = "GET"
                            , rawPathInfo       = "http://" <> authority <> "/resource"
                            , requestHeaderHost = Just "evil.example"
                            , requestHeaders    =
                                [ (HT.hHost, "evil.example")
                                , (HT.hProxyAuthorization, "Basic " <> B64.encode "alice:secret")
                                , ("Forwarded", "for=203.0.113.7")
                                , ("X-Forwarded-For", "203.0.113.7")
                                , ("Proxy-Connection", "keep-alive")
                                , ("cf-ray", "abc123")
                                , ("X-Real-IP", "203.0.113.7")
                                , ("User-Agent", "hprox-test")
                                ]
                            }
                response <- runProxyApp (httpProxy authorizedSettings) proxiedReq
                simpleStatus response `shouldBe` HT.status200
                responseBody response `shouldBe`
                    [ LBS.fromStrict authority
                    , LBS.fromStrict authority
                    , "False"
                    , "False"
                    , "False"
                    , "False"
                    , "False"
                    , "True"
                    ]

-- Keep proxy upstream tests independent of Warp's Windows accept loop.
withRawHttpServer :: (BS.ByteString -> LBS.ByteString) -> (Int -> IO a) -> IO a
withRawHttpServer responseBody action =
    bracket open cleanup run
  where
    open = do
        accepted <- newIORef Nothing
        sock <- openTcpServerSocket
        return (sock, accepted)

    cleanup (sock, accepted) = do
        closeIgnoringErrors sock
        readIORef accepted >>= mapM_ closeIgnoringErrors

    run server@(sock, _) = do
        done <- newEmptyMVar
        _ <- forkIO $ try (acceptAndRespond server) >>= putMVar done
        result <- action . fromIntegral =<< socketPort sock
        serverResult <- timeout 2000000 (takeMVar done)
        case serverResult of
            Just (Left ex) -> throwIO (ex :: SomeException)
            _              -> return result

    acceptAndRespond (sock, accepted) =
        bracket (acceptClient sock accepted) closeIgnoringErrors $ \conn -> do
            requestBytes <- recvHttpRequest conn
            sendHttpResponse conn $ responseBody requestBytes

    acceptClient sock accepted = do
        (conn, _) <- accept sock
        writeIORef accepted (Just conn)
        return conn

openTcpServerSocket :: IO Socket
openTcpServerSocket = bracketOnError open closeIgnoringErrors $ \sock -> do
    setSocketOption sock ReuseAddr 1
    bind sock (SockAddrInet 0 loopbackAddress)
    listen sock (max 2048 maxListenQueue)
    return sock
  where
    open = socket AF_INET Stream defaultProtocol

recvHttpRequest :: Socket -> IO BS.ByteString
recvHttpRequest conn = go BS.empty
  where
    go received
        | "\r\n\r\n" `BS.isInfixOf` received = return received
        | BS.length received > 65536         = ioError $ userError "upstream HTTP request headers exceeded test limit"
        | otherwise                          = do
            chunk <- recvWithTimeout conn
            if BS.null chunk
            then ioError $ userError "upstream HTTP request ended before headers completed"
            else go (received <> chunk)

sendHttpResponse :: Socket -> LBS.ByteString -> IO ()
sendHttpResponse conn body =
    let strictBody = LBS.toStrict body
    in SocketBS.sendAll conn $ BS8.concat
        [ "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
        , BS8.pack (show $ BS.length strictBody)
        , "\r\nConnection: close\r\n\r\n"
        , strictBody
        ]

closeIgnoringErrors :: Socket -> IO ()
closeIgnoringErrors sock = do
    closed <- try (close sock) :: IO (Either IOException ())
    case closed of
        Left _   -> return ()
        Right () -> return ()

observeRawProxyRequestBody :: BS.ByteString -> LBS.ByteString
observeRawProxyRequestBody requestBytes =
    LBS8.unlines
        [ LBS.fromStrict $ headerValue HT.hHost
        , LBS.fromStrict $ headerValue HT.hHost
        , LBS8.pack $ show $ hasHeader HT.hProxyAuthorization
        , LBS8.pack $ show $ hasHeader "Forwarded"
        , LBS8.pack $ show $ hasHeader "X-Forwarded-For"
        , LBS8.pack $ show $ hasHeader "Proxy-Connection"
        , LBS8.pack $ show $ hasHeader "cf-ray"
        , LBS8.pack $ show $ hasHeader "User-Agent"
        ]
  where
    headers = mapMaybe parseHeader $ takeWhile (not . BS.null) $ drop 1 $ map trimCR $ BS8.lines requestBytes
    normalizedHeaders = [(CI.mk name, value) | (name, value) <- headers]

    headerValue name = fromMaybe "" $ lookup name normalizedHeaders
    hasHeader name = lookup name normalizedHeaders /= Nothing

    parseHeader line =
        let (name, rest) = BS8.break (== ':') line
        in if BS.null rest
           then Nothing
           else Just (name, BS8.dropWhile (== ' ') $ BS.drop 1 rest)

    trimCR line
        | "\r" `BS.isSuffixOf` line = BS.init line
        | otherwise                 = line

runProxyApp :: (HC.Manager -> Middleware) -> Request -> IO SResponse
runProxyApp middleware req = do
    manager <- HC.newManager $
        HC.managerSetProxy HC.noProxy HC.defaultManagerSettings
            { HC.managerIdleConnectionCount = 0
            , HC.managerResponseTimeout     = HC.responseTimeoutMicro 2000000
            }
    runSession (srequest $ SRequest req "") (middleware manager fallback)

runConnectApp :: ProxySettings -> Request -> IO SResponse
runConnectApp pset req = runSession (srequest $ SRequest req "") (httpConnectProxy pset fallback)

rawProxyRequest :: Request
rawProxyRequest = defaultRequest
    { requestMethod     = "GET"
    , rawPathInfo       = "http://example.com/resource"
    , requestHeaderHost = Just "example.com"
    }

rawProxyRequestWithAuth :: BS8.ByteString -> Request
rawProxyRequestWithAuth auth = rawProxyRequest
    { requestHeaders = [(HT.hProxyAuthorization, auth)]
    }

proxyRequestForPort :: Int -> BS8.ByteString -> Request
proxyRequestForPort port auth =
    let authority = "127.0.0.1:" <> BS8.pack (show port)
    in (rawProxyRequestWithAuth auth)
        { rawPathInfo       = "http://" <> authority <> "/resource"
        , requestHeaderHost = Just authority
        }

basicAliceSecret :: BS8.ByteString
basicAliceSecret = basicCredential "alice:secret"

basicCredential :: BS8.ByteString -> BS8.ByteString
basicCredential credential = "Basic " <> B64.encode credential

hostHeaderProxyRequest :: Request
hostHeaderProxyRequest = defaultRequest
    { requestMethod     = "GET"
    , rawPathInfo       = "/resource"
    , requestHeaderHost = Just "example.com"
    , requestHeaders    = [("Proxy-Connection", "keep-alive")]
    }

http2ProxyRequest :: Request
http2ProxyRequest = defaultRequest
    { requestMethod     = "GET"
    , rawPathInfo       = "/resource"
    , requestHeaderHost = Just "example.com"
    , requestHeaders    = [("X-Scheme", "http")]
    , httpVersion       = HT.http20
    , isSecure          = True
    }

connectRequest :: Request
connectRequest = defaultRequest
    { requestMethod     = "CONNECT"
    , rawPathInfo       = "example.com:443"
    , requestHeaderHost = Just "example.com:443"
    }

connectRequestFor :: BS8.ByteString -> Int -> HT.HttpVersion -> Request
connectRequestFor host port version =
    let authority = host <> ":" <> BS8.pack (show port)
    in connectRequest
        { rawPathInfo       = authority
        , requestHeaderHost = Just authority
        , requestHeaders    = [(HT.hProxyAuthorization, basicAliceSecret)]
        , httpVersion       = version
        }

getFreePort :: IO Int
getFreePort = bracket open close socketPortInt
  where
    open = do
        sock <- socket AF_INET Stream defaultProtocol
        setSocketOption sock ReuseAddr 1
        bind sock (SockAddrInet 0 loopbackAddress)
        return sock

    socketPortInt sock = fromIntegral <$> socketPort sock

withTcpEchoServer :: (Int -> IO a) -> IO a
withTcpEchoServer action = do
    accepted <- newIORef Nothing
    bracket (open accepted) cleanup run
  where
    open accepted = do
        sock <- openTcpServerSocket
        return (sock, accepted)

    cleanup (sock, accepted) = do
        closeIgnoringErrors sock
        readIORef accepted >>= mapM_ closeIgnoringErrors

    run server@(sock, _) =
        withAsync (acceptAndEcho server) $ \_ ->
            (action . fromIntegral =<< socketPort sock) `finally` cleanup server

    acceptAndEcho (sock, accepted) =
        bracket (acceptClient sock accepted) closeIgnoringErrors echoLoop

    acceptClient sock accepted = do
        (conn, _) <- accept sock
        writeIORef accepted (Just conn)
        return conn

    echoLoop conn = do
        bs <- SocketBS.recv conn 4096
        unless (BS8.null bs) $ do
            SocketBS.sendAll conn bs
            echoLoop conn

-- Exercise the HTTP/1 raw response path without running a nested Warp server.
rawConnectRoundTrip :: IO BS8.ByteString
rawConnectRoundTrip = do
    outbound <- newIORef []
    clientChunks <- newIORef ["ping", ""]
    let targetHost = "127.0.0.1"
        targetPort = 18443
        runTCPClient settings app = do
            CN.getHost settings `shouldBe` targetHost
            CN.getPort settings `shouldBe` targetPort
            inbound <- newEmptyMVar
            app AppData
                { appRead'            = takeMVar inbound
                , appWrite'           = \bytes -> do
                    putMVar inbound bytes
                    putMVar inbound BS.empty
                , appSockAddr'        = SockAddrInet 0 loopbackAddress
                , appLocalAddr'       = Nothing
                , appCloseConnection' = return ()
                , appRawSocket'       = Nothing
                }
        nextClientChunk =
            atomicModifyIORef' clientChunks $ \chunks ->
                case chunks of
                    []     -> ([], BS.empty)
                    x : xs -> (xs, x)
        respondRaw (ResponseRaw raw _) = do
            raw nextClientChunk (\bytes -> modifyIORef' outbound (bytes :))
            return ResponseReceived
        respondRaw _ = expectationFailure "expected HTTP/1 raw CONNECT response" >> return ResponseReceived
    _ <- httpConnectProxyWith runTCPClient authorizedSettings fallback (connectRequestFor targetHost targetPort HT.http11) respondRaw
    sent <- BS.concat . reverse <$> readIORef outbound
    sent `shouldSatisfy` BS8.isPrefixOf "HTTP/1.1 200"
    case BS.breakSubstring "\r\n\r\n" sent of
        (_, body) | not (BS.null body) -> return $ BS.drop 4 body
        _                             -> expectationFailure "raw CONNECT response did not contain an HTTP header terminator" >> return BS.empty

recvWithTimeout :: Socket -> IO BS8.ByteString
recvWithTimeout sock = do
    received <- timeout 2000000 (SocketBS.recv sock 4096)
    case received of
        Just bytes -> return bytes
        Nothing    -> ioError $ userError "timed out waiting for proxy socket response"

loopbackAddress :: HostAddress
loopbackAddress = tupleToHostAddress (127, 0, 0, 1)

fallback :: Application
fallback _req respond = respond $ responseLBS fallbackStatus [("Content-Type", "text/plain")] fallbackBody

fallbackStatus :: HT.Status
fallbackStatus = HT.mkStatus 418 "fallback"

fallbackBody :: LBS.ByteString
fallbackBody = "fallback"

authRequiredSettings :: ProxySettings
authRequiredSettings = baseSettings
    { proxyAuth = Just (const False)
    }

hiddenAuthSettings :: ProxySettings
hiddenAuthSettings = authRequiredSettings
    { hideProxyAuth = True
    }

authorizedSettings :: ProxySettings
authorizedSettings = baseSettings
    { proxyAuth = Just (== "alice:secret")
    }

baseSettings :: ProxySettings
baseSettings = ProxySettings
    { proxyAuth      = Nothing
    , passPrompt     = Just "hprox"
    , wsRemote       = Nothing
    , revRemoteMap   = []
    , hideProxyAuth  = False
    , naivePadding   = False
    , acmeThumbprint = Nothing
    , logger         = \_ _ -> return ()
    }

