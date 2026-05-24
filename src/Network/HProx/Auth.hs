-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.Auth
  ( loadProxyAuth
  ) where

import Control.Monad         (when)
import Data.ByteString.Char8 qualified as BS8
import Data.HashMap.Strict   qualified as HM
import Data.Maybe            (catMaybes)

import Network.HProx.Log
import Network.HProx.Util

loadProxyAuth :: Logger -> Maybe FilePath -> IO (Maybe (BS8.ByteString -> Bool))
loadProxyAuth _ Nothing = return Nothing
loadProxyAuth logger (Just f) = do
  logger INFO $ "read username and passwords from " <> toLogStr f
  userList <- zip [1 :: Int ..] . map stripTrailingCarriageReturn . BS8.lines <$> BS8.readFile f
  let anyPlaintext = any (\(_, line) -> length (BS8.elemIndices ':' line) /= 2) userList
      processUser (lineNumber, userpass) = case passwordReader userpass of
        Nothing           -> do
          logger WARN $ "unable to parse line " <> toLogStr lineNumber <> malformedLineUserContext userpass <> " from password file"
          return Nothing
        Just (user, pass) -> do
          salted <- hashPasswordWithRandomSalt pass
          logger TRACE $ "parsed user (with salted password) from password file: " <> toLogStr (passwordWriter user salted)
          return $ Just (user, salted)
  passwordByUser <- HM.fromList . catMaybes <$> mapM processUser userList
  when anyPlaintext $ do
    logger INFO $ "writing back to password file " <> toLogStr f
    BS8.writeFile f (BS8.unlines [ passwordWriter u p | (u, p) <- HM.toList passwordByUser])
  let verify line = do
        idx <- BS8.elemIndex ':' line
        let user = BS8.take idx line
            pass = BS8.drop (idx + 1) line
        targetPass <- HM.lookup user passwordByUser
        return $ verifyPassword targetPass pass
  return $ Just (\line -> verify line == Just True)

stripTrailingCarriageReturn :: BS8.ByteString -> BS8.ByteString
stripTrailingCarriageReturn line
    | "\r" `BS8.isSuffixOf` line = BS8.init line
    | otherwise                  = line

malformedLineUserContext :: BS8.ByteString -> LogStr
malformedLineUserContext line =
  case BS8.elemIndex ':' line of
    Nothing -> ""
    Just 0  -> ""
    Just i  -> " for user " <> toLogStr (BS8.take i line)
