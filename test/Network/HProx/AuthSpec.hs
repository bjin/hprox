-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.AuthSpec
  ( spec
  ) where

import Control.Concurrent        (threadDelay)
import Control.Concurrent.Async  (cancel, withAsync)
import Control.Exception         (SomeException, bracket, finally, try)
import Data.ByteString           qualified as BS
import Data.ByteString.Char8     qualified as BS8
import Data.IORef
import Data.Maybe                (mapMaybe)
import Network.HTTP.Types        qualified as HT
import Network.Socket
import Network.Socket.ByteString qualified as SocketBS
import Network.Wai               (Application, responseLBS)
import System.Directory          (removeFile)
import System.IO                 (hClose, openTempFile)
import System.Log.FastLogger     qualified as FL

import Network.HProx
import Network.HProx.Auth
import Network.HProx.Util

import Test.Hspec

spec :: Spec
spec =
  describe "auth file handling" $ do
    it "does not require proxy auth when no auth file is configured" $
      withHProx Nothing $ \port -> do
        response <- rawHttpRequest port $ BS8.concat
          [ "GET http://127.0.0.1:"
          , BS8.pack (show port)
          , "/.hprox/health HTTP/1.1\r\nHost: 127.0.0.1:"
          , BS8.pack (show port)
          , "\r\n\r\n"
          ]
        responseStatus response `shouldBe` HT.status200

    it "hashes plaintext entries, ignores invalid lines, and rewrites salted entries" $
      withTempAuthFile "alice:secret\ninvalid-line\nbob:too:many:fields\n" $ \path -> do
        withHProx (Just path) $ \_port -> do
          rewritten <- BS8.lines <$> BS.readFile path
          case rewritten of
            [line] -> case passwordReader line of
              Just ("alice", Salted salt hash) -> do
                line `shouldBe` passwordWriter "alice" (PasswordSalted salt hash)
                verifyPassword (PasswordSalted salt hash) "secret" `shouldBe` True
                verifyPassword (PasswordSalted salt hash) "wrong" `shouldBe` False
              parsed -> expectationFailure $ "unexpected rewritten auth line: " <> show parsed
            lines' -> expectationFailure $ "unexpected rewritten auth file line count: " <> show (length lines')

    it "keeps an already salted file unchanged" $ do
      salted <- hashPasswordWithRandomSalt (PlainText "secret")
      let line = passwordWriter "alice" salted
          original = line <> "\n"
      withTempAuthFile original $ \path -> do
        withHProx (Just path) $ \_port -> do
          rewritten <- BS.readFile path
          rewritten `shouldBe` original

    it "normalizes CRLF plaintext entries before hashing and verification" $
      withTempAuthFile "alice:secret\r\n" $ \path -> do
        Just verifier <- loadProxyAuth (\_ _ -> return ()) (Just path)
        verifier "alice:secret" `shouldBe` True
        verifier "alice:secret\r" `shouldBe` False
        [rewritten] <- BS8.lines <$> BS.readFile path
        case passwordReader rewritten of
          Just ("alice", Salted salt hash) ->
            verifyPassword (PasswordSalted salt hash) "secret" `shouldBe` True
          parsed -> expectationFailure $ "unexpected rewritten auth line: " <> show parsed

    it "redacts malformed auth-file lines in logs" $
      withTempAuthFile "alice:secret:hash:extra\nraw-secret-without-separators\n" $ \path -> do
        logs <- newIORef []
        _ <- loadProxyAuth (\_ msg -> modifyIORef' logs (BS8.append (FL.fromLogStr msg) "\n" :)) (Just path)
        renderedLogs <- BS.concat . reverse <$> readIORef logs
        renderedLogs `shouldSatisfy` BS8.isInfixOf "line 1"
        renderedLogs `shouldSatisfy` BS8.isInfixOf "alice"
        renderedLogs `shouldSatisfy` BS8.isInfixOf "line 2"
        renderedLogs `shouldNotSatisfy` BS8.isInfixOf "secret"
        renderedLogs `shouldNotSatisfy` BS8.isInfixOf "hash"
        renderedLogs `shouldNotSatisfy` BS8.isInfixOf "extra"
        renderedLogs `shouldNotSatisfy` BS8.isInfixOf "raw-secret-without-separators"

withTempAuthFile :: BS.ByteString -> (FilePath -> IO a) -> IO a
withTempAuthFile contents action = bracket create cleanup (action . fst)
  where
    create = do
      (path, handle) <- openTempFile "." "hprox-auth-test"
      BS.hPut handle contents
      hClose handle
      return (path, ())

    cleanup (path, ()) = removeFile path

withHProx :: Maybe FilePath -> (Int -> IO a) -> IO a
withHProx authPath action = do
  port <- getFreePort
  let conf = defaultConfig
        { _bind     = Just "127.0.0.1"
        , _port     = port
        , _auth     = authPath
        , _log      = "none"
        , _loglevel = NONE
        }
  withAsync (run fallback conf) $ \server -> do
    waitForHealth port
    action port `finally` cancel server

fallback :: Application
fallback _req respond = respond $ responseLBS HT.status200 [] "fallback"


getFreePort :: IO Int
getFreePort = bracket open close socketPortInt
  where
    open = do
      sock <- socket AF_INET Stream defaultProtocol
      setSocketOption sock ReuseAddr 1
      bind sock (SockAddrInet 0 (tupleToHostAddress (127, 0, 0, 1)))
      return sock

    socketPortInt sock = fromIntegral <$> socketPort sock

waitForHealth :: Int -> IO ()
waitForHealth port = go (200 :: Int)
  where
    go 0 = expectationFailure "hprox server did not become ready"
    go attempts = do
      response <- try (rawHttpRequest port $ BS8.concat
        [ "GET /.hprox/health HTTP/1.1\r\nHost: 127.0.0.1:"
        , BS8.pack (show port)
        , "\r\n\r\n"
        ]) :: IO (Either SomeException BS.ByteString)
      case response of
        Right bytes | responseStatus bytes == HT.status200 -> return ()
        _                                                  -> threadDelay 10000 >> go (attempts - 1)

rawHttpRequest :: Int -> BS.ByteString -> IO BS.ByteString
rawHttpRequest port request = bracket open close sendReceive
  where
    open = do
      sock <- socket AF_INET Stream defaultProtocol
      connect sock (SockAddrInet (fromIntegral port) (tupleToHostAddress (127, 0, 0, 1)))
      return sock

    sendReceive sock = do
      SocketBS.sendAll sock request
      SocketBS.recv sock 4096

responseStatus :: BS.ByteString -> HT.Status
responseStatus response =
  case mapMaybe parseStatusLine (take 1 $ BS8.lines response) of
    status : _ -> status
    []         -> HT.mkStatus 0 "invalid response"

parseStatusLine :: BS.ByteString -> Maybe HT.Status
parseStatusLine line = case BS8.words line of
  _version : codeBytes : reasonWords -> do
    (code, rest) <- BS8.readInt codeBytes
    if BS.null rest
      then Just $ HT.mkStatus code $ BS8.unwords reasonWords
      else Nothing
  _ -> Nothing
