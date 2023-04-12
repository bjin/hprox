-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.
{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import qualified Data.ByteString.Lazy.Char8 as LBS8
import qualified Network.HTTP.Types         as HT
import           Network.Wai

import           Network.HProx

dumbApp :: Application
dumbApp _req respond =
    respond $ responseLBS
        HT.status200
        [("Content-Type", "text/html")] $
        LBS8.unlines [ "<html><body><h1>It works!</h1>"
                     , "<p>This is the default web page for this server.</p>"
                     , "<p>The web server software is running but no content has been added, yet.</p>"
                     , "</body></html>"
                     ]

main :: IO ()
main = getConfig >>= run dumbApp
