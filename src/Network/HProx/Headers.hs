-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.Headers
  ( cdnLoopHeader
  , forwardedHostHeader
  , forwardedProtoHeader
  , headerValueEquals
  , isCDNHeader
  , isForwardedHeader
  , isProxyHeader
  , isProxyStripHeader
  , xRealIPHeader
  , xSchemeHeader
  ) where

import Data.ByteString           qualified as BS
import Data.CaseInsensitive      qualified as CI
import Network.HTTP.Types.Header (HeaderName)

cdnLoopHeader :: HeaderName
cdnLoopHeader = "cdn-loop"

forwardedHostHeader :: HeaderName
forwardedHostHeader = "x-forwarded-host"

forwardedProtoHeader :: HeaderName
forwardedProtoHeader = "x-forwarded-proto"

xRealIPHeader :: HeaderName
xRealIPHeader = "X-Real-IP"

xSchemeHeader :: HeaderName
xSchemeHeader = "X-Scheme"

isProxyHeader :: HeaderName -> Bool
isProxyHeader header = "proxy" `BS.isPrefixOf` CI.foldedCase header

isForwardedHeader :: HeaderName -> Bool
isForwardedHeader header =
  folded == "forwarded" || "x-forwarded" `BS.isPrefixOf` folded
  where
    folded = CI.foldedCase header

isCDNHeader :: HeaderName -> Bool
isCDNHeader header = "cf-" `BS.isPrefixOf` CI.foldedCase header || header == cdnLoopHeader

headerValueEquals :: BS.ByteString -> BS.ByteString -> Bool
headerValueEquals expected actual = CI.mk expected == CI.mk actual

isProxyStripHeader :: HeaderName -> Bool
isProxyStripHeader header =
  isProxyHeader header || isForwardedHeader header || isCDNHeader header ||
  header == xRealIPHeader || header == xSchemeHeader
