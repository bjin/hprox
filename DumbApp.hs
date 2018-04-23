{-# LANGUAGE OverloadedStrings #-}

module DumbApp (dumbApp) where

import qualified Data.ByteString            as BS
import qualified Data.ByteString.Lazy.Char8 as LBS8
import qualified Network.HTTP.Types         as HT
import           Network.Wai

import           Control.Applicative        ((<|>))

dumbApp :: Application
dumbApp req respond | pathInfo req == ["get", "hprox.pac"],
                      Just host' <- lookup "x-forwarded-host" (requestHeaders req) <|> requestHeaderHost req =
    let issecure = case lookup "x-forwarded-proto" (requestHeaders req) of
            Just proto -> proto == "https"
            Nothing    -> isSecure req
        scheme = if issecure then "HTTPS" else "PROXY"
        defaultPort = if issecure then ":443" else ":80"
        host | 58 `BS.elem` host' = host' -- ':'
             | otherwise          = host' `BS.append` defaultPort
    in respond $ responseLBS
           HT.status200
           [("Content-Type", "application/x-ns-proxy-autoconfig")] $
           LBS8.unlines [ "function FindProxyForURL(url, host) {"
                        , LBS8.fromChunks ["  return \"", scheme, " ", host, "\";"]
                        , "}"
                        ]

dumbApp _req respond =
    respond $ responseLBS
        HT.status200
        [("Content-Type", "text/html")] $
        LBS8.unlines [ "<html><body><h1>It works!</h1>"
                     , "<p>This is the default web page for this server.</p>"
                     , "<p>The web server software is running but no content has been added, yet.</p>"
                     , "</body></html>"
                     ]
