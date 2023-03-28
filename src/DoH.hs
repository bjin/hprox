-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.
{-# LANGUAGE OverloadedStrings #-}

module DoH (
  createResolver,
  dnsOverHTTPS
) where

import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Char8      as BS8
import qualified Data.ByteString.Lazy       as LBS
import qualified Network.DNS                as DNS
import qualified Network.HTTP.Types         as HT

import           Network.Wai
import           Util

createResolver :: String -> (DNS.Resolver -> IO a) -> IO a
createResolver remote handle = do
    seed <- DNS.makeResolvSeed conf
    DNS.withResolver seed handle
  where
    (h, p) = parseHostPortWithDefault 53 (BS8.pack remote)
    info = DNS.RCHostPort (BS8.unpack h) (fromIntegral p)

    conf = DNS.defaultResolvConf { DNS.resolvInfo = info }

dnsOverHTTPS :: DNS.Resolver -> Middleware
dnsOverHTTPS resolver fallback req respond
    | pathInfo req == ["dns-query"] && isSecure req = handleDoH resolver req respond
    | otherwise = fallback req respond

handleDoH :: DNS.Resolver -> Application
handleDoH resolver req respond
    | requestMethod req == "GET",
      [("dns", Just dnsStr)] <- queryString req,
      Right dnsQuery <- Base64.decodeUnpadded dnsStr,
      Right (DNS.DNSMessage { DNS.question = [q], DNS.header = DNS.DNSHeader {DNS.identifier = ident} }) <- DNS.decode dnsQuery =
        handleQuery ident q
    | requestMethod req == "POST",
      KnownLength len <- requestBodyLength req,
      len <= 4096 = do
        dnsQuery <- getRequestBodyChunk req
        case DNS.decode dnsQuery of
            Right (DNS.DNSMessage { DNS.question = [q], DNS.header = DNS.DNSHeader {DNS.identifier = ident} }) -> handleQuery ident q
            _ -> respond errorResp
    | otherwise = respond errorResp
  where
    errorResp = responseLBS HT.status400 [("Content-Type", "text/plain")] "invalid dns-over-https request"

    handleQuery ident query = do
        resp <- DNS.lookupRaw resolver (DNS.qname query) (DNS.qtype query)
        respond $ case resp of
            Left _ -> errorResp
            Right dnsResp ->
                let encoded = DNS.encode (dnsResp {DNS.header = (DNS.header dnsResp) {DNS.identifier = ident} }) in
                    responseLBS HT.status200
                        [("Content-Type", "application/dns-message"),
                         ("Content-Length", BS8.pack $ show (BS8.length encoded))]
                        (LBS.fromStrict encoded)
