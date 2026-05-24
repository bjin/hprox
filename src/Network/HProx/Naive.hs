-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

module Network.HProx.Naive
  ( PaddingType(..)
  , addPaddingConduit
  , parseRequestForPadding
  , prepareResponseForPadding
  , removePaddingConduit
  ) where

import Control.Monad             (replicateM, unless)
import Control.Monad.IO.Class    (liftIO)
import Data.Binary.Builder       qualified as BB
import Data.ByteString           qualified as BS
import Data.ByteString.Char8     qualified as BS8
import Data.ByteString.Lazy      qualified as LBS
import Data.Conduit.Binary       qualified as CB
import Data.Maybe                (listToMaybe, mapMaybe)
import Network.HTTP.Types.Header qualified as HT
import System.Random             (uniformR)
import System.Random.Stateful    (applyAtomicGen, globalStdGen, runStateGen, uniformRM)

import Data.Conduit
import Network.Wai

randomPaddingMinLength :: Int
randomPaddingMinLength = 32

randomPaddingMaxLength :: Int
randomPaddingMaxLength = 63

randomPaddingPrefixLength :: Int
randomPaddingPrefixLength = 24

randomPadding :: IO BS8.ByteString
randomPadding = applyAtomicGen generate globalStdGen
  where
    nonHuffman = "!#$()+<>?@[]^`{}"
    countNonHuffman = length nonHuffman

    generate g0 = runStateGen g0 $ \gen -> do
        len <- uniformRM (randomPaddingMinLength, randomPaddingMaxLength) gen
        prefix <- replicateM randomPaddingPrefixLength $ do
            idx <- uniformRM (0, countNonHuffman - 1) gen
            return $ nonHuffman !! idx
        return (BS8.pack (prefix ++ replicate (len - randomPaddingPrefixLength) '~'))

randInt :: Int -> Int -> IO Int
randInt minv maxv = applyAtomicGen (uniformR (minv, maxv)) globalStdGen

-- https://github.com/klzgrad/naiveproxy/blob/master/src/net/tools/naive/naive_protocol.h#L30C12-L30C23
data PaddingType = NoPadding
                 | Variant1
  deriving (Show, Eq, Ord)

parsePaddingType :: BS8.ByteString -> Maybe PaddingType
parsePaddingType "0" = Just NoPadding
parsePaddingType "1" = Just Variant1
parsePaddingType _   = Nothing

showPaddingType :: PaddingType -> BS8.ByteString
showPaddingType NoPadding = "0"
showPaddingType Variant1  = "1"

legacyPaddingHeader :: HT.HeaderName
legacyPaddingHeader = "Padding"

paddingTypeRequestHeader :: HT.HeaderName
paddingTypeRequestHeader = "Padding-Type-Request"

paddingTypeReplyHeader :: HT.HeaderName
paddingTypeReplyHeader = "Padding-Type-Reply"

type PaddingConduit = ConduitT BS.ByteString BS.ByteString IO ()

noPaddingConduit :: PaddingConduit
noPaddingConduit = awaitForever yield

addPaddingConduit :: PaddingType -> PaddingConduit
addPaddingConduit NoPadding = noPaddingConduit
addPaddingConduit Variant1  = addPaddingVariant1 countPaddingsVariant1

removePaddingConduit :: PaddingType -> PaddingConduit
removePaddingConduit NoPadding = noPaddingConduit
removePaddingConduit Variant1  = removePaddingVariant1 countPaddingsVariant1

parseRequestForPadding :: Request -> Maybe PaddingType
parseRequestForPadding req
    | Just paddingTypesStr <- lookup paddingTypeRequestHeader (requestHeaders req) =
        listToMaybe $ mapMaybe parsePaddingType $ BS8.split ',' paddingTypesStr
    | Just _ <- lookup legacyPaddingHeader (requestHeaders req) = Just Variant1
    | otherwise                                                 = Nothing

prepareResponseForPadding :: Maybe PaddingType -> IO [HT.Header]
prepareResponseForPadding Nothing = return []
prepareResponseForPadding (Just paddingType) = do
    rndPadding <- randomPadding
    return [(legacyPaddingHeader, rndPadding), (paddingTypeReplyHeader, showPaddingType paddingType)]

-- see: https://github.com/klzgrad/naiveproxy/blob/master/src/net/tools/naive/naive_protocol.h#L34
countPaddingsVariant1 :: Int
countPaddingsVariant1 = 8

variant1HeaderLength :: Int
variant1HeaderLength = 3

variant1MaxPaddingLength :: Int
variant1MaxPaddingLength = 255

variant1MaxFrameLength :: Int
variant1MaxFrameLength = 65535

variant1MaxPayloadLength :: Int
variant1MaxPayloadLength = variant1MaxFrameLength - variant1HeaderLength - variant1MaxPaddingLength

variant1SmallPayloadThreshold :: Int
variant1SmallPayloadThreshold = 400

variant1LargePayloadThreshold :: Int
variant1LargePayloadThreshold = 1024

variant1SplitMinLength :: Int
variant1SplitMinLength = 200

variant1SplitMaxLength :: Int
variant1SplitMaxLength = 300

variant1MinFullPaddingLength :: Int
variant1MinFullPaddingLength = 100

addPaddingVariant1 :: Int -> PaddingConduit
addPaddingVariant1 0 = noPaddingConduit
addPaddingVariant1 n = do
    mbs <- await
    case mbs of
        Nothing -> return ()
        Just bs | BS.null bs -> return ()
        Just bs -> do
            let remaining = min (BS.length bs) variant1MaxPayloadLength
            toConsume <- if remaining > variant1SmallPayloadThreshold && remaining < variant1LargePayloadThreshold
                         then liftIO $ randInt variant1SplitMinLength variant1SplitMaxLength
                         else return remaining
            let (bs0, bs1) = BS.splitAt toConsume bs
            unless (BS.null bs1) $ leftover bs1
            let len = BS.length bs0
                minPaddingLen = if len < variant1MinFullPaddingLength then variant1MaxPaddingLength - len else 1
            paddingLen <- liftIO $ randInt minPaddingLen variant1MaxPaddingLength
            let header = mconcat (map (BB.singleton.fromIntegral) [len `div` 256, len `mod` 256, paddingLen])
                body   = BB.fromByteString bs0
                tailer = BB.fromByteString (BS.replicate paddingLen 0)
            yield $ LBS.toStrict $ BB.toLazyByteString (header <> body <> tailer)
            addPaddingVariant1 (n - 1)

removePaddingVariant1 :: Int -> PaddingConduit
removePaddingVariant1 0 = noPaddingConduit
removePaddingVariant1 n = do
    header <- CB.take 3
    case LBS.unpack header of
        [b0, b1, b2] -> do
            let len = fromIntegral b0 * 256 + fromIntegral b1
                paddingLen = fromIntegral b2
            bs <- CB.take (fromIntegral (len + paddingLen))
            if LBS.length bs /= len + paddingLen
                then return ()
                else yield (LBS.toStrict $ LBS.take len bs) >> removePaddingVariant1 (n - 1)
        _otherwise   -> return ()
