-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

module Network.HProx.DoH
  ( DoHRequest(..)
  , createResolver
  , dnsOverHTTPS
  , dnsOverHTTPSWithLookup
  , parseDoHRequest
  ) where

import Data.ByteString.Base64.URL qualified as Base64
import Data.ByteString.Char8      qualified as BS8
import Data.ByteString.Lazy       qualified as LBS
import Network.DNS
    (DNSHeader(..), DNSMessage(..), Question(..), ResolvConf(..), Resolver)
import Network.DNS                qualified as DNS
import Network.HTTP.Types         qualified as HT

import Network.Wai

import Network.HProx.Util

data DoHRequest = DoHRequest
  { dohIdentifier :: !DNS.Identifier
  , dohQuestion   :: !Question
  }
  deriving (Eq, Show)

maxPostBodyLength :: Int
maxPostBodyLength = 4096

createResolver :: String -> (Resolver -> IO a) -> IO a
createResolver remote handle = do
    seed <- DNS.makeResolvSeed conf
    DNS.withResolver seed handle
  where
    (h, p) = parseHostPortWithDefault 53 (BS8.pack remote)
    info = DNS.RCHostPort (BS8.unpack h) (fromIntegral p)

    conf = DNS.defaultResolvConf { resolvInfo = info }

dnsOverHTTPS :: Resolver -> Middleware
dnsOverHTTPS resolver =
    dnsOverHTTPSWithLookup $ \Question{..} -> DNS.lookupRaw resolver qname qtype

dnsOverHTTPSWithLookup :: (Question -> IO (Either DNS.DNSError DNSMessage)) -> Middleware
dnsOverHTTPSWithLookup lookupRaw fallback req respond
    | pathInfo req == ["dns-query"] && isSecure req = handleDoH lookupRaw req respond
    | otherwise = fallback req respond

handleDoH :: (Question -> IO (Either DNS.DNSError DNSMessage)) -> Application
handleDoH lookupRaw req respond = do
    dohRequest <- parseDoHRequest req
    case dohRequest of
      Nothing -> respond errorResp
      Just DoHRequest{..} -> do
        resp <- lookupRaw dohQuestion
        respond $ case resp of
          Left _    -> errorResp
          Right msg -> encodeDoHResponse dohIdentifier msg

parseDoHRequest :: Request -> IO (Maybe DoHRequest)
parseDoHRequest req
    | requestMethod req == "GET",
      [("dns", Just dnsStr)] <- queryString req =
        return $ decodeDoHQuery =<< either (const Nothing) Just (Base64.decodeUnpadded dnsStr)
    | requestMethod req == "POST",
      KnownLength len <- requestBodyLength req,
      len <= fromIntegral maxPostBodyLength =
        decodeDoHQuery <$> getRequestBodyChunk req
    | otherwise = return Nothing

decodeDoHQuery :: BS8.ByteString -> Maybe DoHRequest
decodeDoHQuery dnsQuery =
    case DNS.decode dnsQuery of
      Right (DNSMessage { question = [q], header = DNSHeader {..} }) ->
        Just DoHRequest
          { dohIdentifier = identifier
          , dohQuestion = q
          }
      _otherwise -> Nothing

encodeDoHResponse :: DNS.Identifier -> DNSMessage -> Response
encodeDoHResponse ident dnsResp@DNSMessage{header = header} =
    let encoded = DNS.encode (dnsResp {header = header {identifier = ident} })
    in responseKnownLength HT.status200
         [("Content-Type", "application/dns-message")]
         (LBS.fromStrict encoded)

errorResp :: Response
errorResp = responseLBS HT.status400 [("Content-Type", "text/plain")] "invalid dns-over-https request"
