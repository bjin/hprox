-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

module Network.HProx.Util
  ( parseHostPort
  , parseHostPortWithDefault
  , randomPadding
  , randomPaddingLength
  ) where

import Control.Monad          (replicateM)
import Data.ByteString        qualified as BS
import Data.ByteString.Char8  qualified as BS8
import Data.Maybe             (fromMaybe)
import Data.Word              (Word8)
import System.Random          (uniformR)
import System.Random.Stateful
    (applyAtomicGen, globalStdGen, runStateGen, uniformRM)


parseHostPort :: BS.ByteString -> Maybe (BS.ByteString, Int)
parseHostPort hostPort = do
    lastColon <- BS8.elemIndexEnd ':' hostPort
    port <- BS8.readInt (BS.drop (lastColon+1) hostPort) >>= checkPort
    return (BS.take lastColon hostPort, port)
  where
    checkPort (p, bs)
        | BS.null bs && 1 <= p && p <= 65535 = Just p
        | otherwise                          = Nothing

parseHostPortWithDefault :: Int -> BS.ByteString -> (BS.ByteString, Int)
parseHostPortWithDefault defaultPort hostPort =
    fromMaybe (hostPort, defaultPort) $ parseHostPort hostPort

randomPadding :: IO BS.ByteString
randomPadding = applyAtomicGen generate globalStdGen
  where
    nonHuffman = "!#$()+<>?@[]^`{}"
    countNonHuffman = length nonHuffman

    generate g0 = runStateGen g0 $ \gen -> do
        len <- uniformRM (32, 63) gen
        prefix <- replicateM 24 $ do
            idx <- uniformRM (0, countNonHuffman - 1) gen
            return $ nonHuffman !! idx
        return (BS8.pack (prefix ++ replicate (len - 24) '~'))

randomPaddingLength :: IO Int
randomPaddingLength = applyAtomicGen (uniformR (1, 255)) globalStdGen
