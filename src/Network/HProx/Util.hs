-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

module Network.HProx.Util
  ( Password (..)
  , PasswordSalted (..)
  , hashPasswordWithRandomSalt
  , parseHostPort
  , parseHostPortWithDefault
  , passwordReader
  , passwordWriter
  , responseKnownLength
  , splitBy
  , verifyPassword
  ) where

import Data.ByteString       qualified as BS
import Data.ByteString.Char8 qualified as BS8
import Data.ByteString.Lazy  qualified as LBS
import Data.Maybe            (fromMaybe)

import Network.HTTP.Types (ResponseHeaders, Status)
import Network.Wai

import Crypto.Error           (CryptoFailable (..))
import Crypto.KDF.Argon2      qualified as Argon2
import Crypto.Random          (MonadRandom (getRandomBytes))
import Data.ByteString.Base64 qualified as Base64

data Password = PlainText BS.ByteString
              | Salted BS.ByteString BS.ByteString
    deriving (Show, Eq)

data PasswordSalted = PasswordSalted BS.ByteString BS.ByteString
    deriving (Show, Eq)

splitBy :: Eq a => a -> [a] -> [[a]]
splitBy _ [] = [[]]
splitBy c (x:xs)
  | c == x    = [] : splitBy c xs
  | otherwise = let y:ys = splitBy c xs in (x:y):ys

passwordReader :: BS.ByteString -> Maybe (BS.ByteString, Password)
passwordReader line = case BS8.split ':' line of
    [user, pass]         -> Just (user, PlainText pass)
    [user, salt, hashed] -> case (Base64.decode salt, Base64.decode hashed) of
                                (Right salt', Right hashed') -> Just (user, Salted salt' hashed')
                                _                            -> Nothing
    _                    -> Nothing

passwordWriter :: BS.ByteString -> PasswordSalted -> BS.ByteString
passwordWriter user (PasswordSalted salt hash) =
    BS.concat [user , ":" , Base64.encode salt , ":" , Base64.encode hash]

hashPasswordWithRandomSalt :: Password -> IO PasswordSalted
hashPasswordWithRandomSalt (PlainText pass) = do
    salt <- getRandomBytes 24
    case Argon2.hash Argon2.defaultOptions pass salt 48 of
        CryptoFailed err -> error ("unable to hash password with salt: " ++ show err)
        CryptoPassed h   -> return (PasswordSalted salt h)
hashPasswordWithRandomSalt (Salted salt h) = return (PasswordSalted salt h)

verifyPassword :: PasswordSalted -> BS8.ByteString -> Bool
verifyPassword (PasswordSalted salt hashed) pass =
    case Argon2.hash Argon2.defaultOptions pass salt 48 of
        CryptoFailed _ -> False
        CryptoPassed h -> h == hashed

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

responseKnownLength :: Status -> ResponseHeaders -> LBS.ByteString -> Response
responseKnownLength status headers bs = responseLBS status (headers ++ [("Content-Length", BS8.pack $ show (LBS.length bs))]) bs
