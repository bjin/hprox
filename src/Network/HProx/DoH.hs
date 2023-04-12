-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

module Network.HProx.DoH
  ( createResolver
  , dnsOverHTTPS
  ) where

import Data.ByteString.Base64.URL qualified as Base64
import Data.ByteString.Char8      qualified as BS8
import Data.ByteString.Lazy       qualified as LBS
import Network.DNS
    (DNSHeader (..), DNSMessage (..), Question (..), ResolvConf (..), Resolver)
import Network.DNS                qualified as DNS
import Network.HTTP.Types         qualified as HT

import Network.Wai

import Network.HProx.Util

createResolver :: String -> (Resolver -> IO a) -> IO a
createResolver remote handle = do
    seed <- DNS.makeResolvSeed conf
    DNS.withResolver seed handle
  where
    (h, p) = parseHostPortWithDefault 53 (BS8.pack remote)
    info = DNS.RCHostPort (BS8.unpack h) (fromIntegral p)

    conf = DNS.defaultResolvConf { resolvInfo = info }

dnsOverHTTPS :: Resolver -> Middleware
dnsOverHTTPS resolver fallback req respond
    | pathInfo req == ["dns-query"] && isSecure req = handleDoH resolver req respond
    | otherwise = fallback req respond

handleDoH :: Resolver -> Application
handleDoH resolver req respond
    | requestMethod req == "GET",
      [("dns", Just dnsStr)] <- queryString req,
      Right dnsQuery <- Base64.decodeUnpadded dnsStr,
      Right (DNSMessage { question = [q], header = DNSHeader {..} }) <- DNS.decode dnsQuery =
        handleQuery identifier q
    | requestMethod req == "POST",
      KnownLength len <- requestBodyLength req,
      len <= 4096 = do
        dnsQuery <- getRequestBodyChunk req
        case DNS.decode dnsQuery of
            Right (DNSMessage { question = [q], header = DNSHeader {..} }) -> handleQuery identifier q
            _ -> respond errorResp
    | otherwise = respond errorResp
  where
    errorResp = responseLBS HT.status400 [("Content-Type", "text/plain")] "invalid dns-over-https request"

    handleQuery ident Question{..} = do
        resp <- DNS.lookupRaw resolver qname qtype
        respond $ case resp of
            Left _ -> errorResp
            Right dnsResp@DNSMessage{header = header} ->
                let encoded = DNS.encode (dnsResp {header = header {identifier = ident} }) in
                    responseLBS HT.status200
                        [("Content-Type", "application/dns-message"),
                         ("Content-Length", BS8.pack $ show (BS8.length encoded))]
                        (LBS.fromStrict encoded)
