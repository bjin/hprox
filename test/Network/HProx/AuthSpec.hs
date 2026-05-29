-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.AuthSpec
  ( spec
  ) where

import Control.Exception     (bracket)
import Data.ByteString       qualified as BS
import Data.ByteString.Char8 qualified as BS8
import Data.IORef
import System.Directory      (removeFile)
import System.IO             (hClose, openTempFile)
import System.Log.FastLogger qualified as FL

import Network.HProx.Auth
import Network.HProx.Util

import Test.Hspec

spec :: Spec
spec =
    describe "auth file handling" $ do
        it "does not require proxy auth when no auth file is configured" $ do
            verifier <- loadProxyAuth (\_ _ -> return ()) Nothing
            case verifier of
                Nothing -> return ()
                Just _  -> expectationFailure "expected no proxy auth verifier"

        it "hashes plaintext entries, ignores invalid lines, and rewrites salted entries" $
            withTempAuthFile "alice:secret\ninvalid-line\nbob:too:many:fields\n" $ \path -> do
                verifier <- loadProxyAuth (\_ _ -> return ()) (Just path)
                case verifier of
                    Just verify -> do
                        verify "alice:secret" `shouldBe` True
                        verify "alice:wrong" `shouldBe` False
                    Nothing -> expectationFailure "expected proxy auth verifier"
                rewritten <- BS8.lines <$> BS.readFile path
                case rewritten of
                    [line] -> case passwordReader line of
                        Just ("alice", Salted salt hash) -> do
                            line `shouldBe` passwordWriter "alice" (PasswordSalted salt hash)
                            verifyPassword (PasswordSalted salt hash) "secret" `shouldBe` True
                            verifyPassword (PasswordSalted salt hash) "wrong" `shouldBe` False
                        parsed -> expectationFailure $ "unexpected rewritten auth line: " <> show parsed
                    lines' -> expectationFailure $ "unexpected rewritten auth file line count: " <> show (length lines')

        it "keeps an already salted file unchanged" $ do
            salted <- hashPasswordWithRandomSalt (PlainText "secret")
            let line = passwordWriter "alice" salted
                original = line <> "\n"
            withTempAuthFile original $ \path -> do
                _ <- loadProxyAuth (\_ _ -> return ()) (Just path)
                rewritten <- BS.readFile path
                rewritten `shouldBe` original

        it "normalizes CRLF plaintext entries before hashing and verification" $
            withTempAuthFile "alice:secret\r\n" $ \path -> do
                Just verifier <- loadProxyAuth (\_ _ -> return ()) (Just path)
                verifier "alice:secret" `shouldBe` True
                verifier "alice:secret\r" `shouldBe` False
                [rewritten] <- BS8.lines <$> BS.readFile path
                case passwordReader rewritten of
                    Just ("alice", Salted salt hash) ->
                        verifyPassword (PasswordSalted salt hash) "secret" `shouldBe` True
                    parsed -> expectationFailure $ "unexpected rewritten auth line: " <> show parsed

        it "redacts malformed auth-file lines in logs" $
            withTempAuthFile "alice:secret:hash:extra\nraw-secret-without-separators\n" $ \path -> do
                logs <- newIORef []
                _ <- loadProxyAuth (\_ msg -> modifyIORef' logs (BS8.append (FL.fromLogStr msg) "\n" :)) (Just path)
                renderedLogs <- BS.concat . reverse <$> readIORef logs
                renderedLogs `shouldSatisfy` BS8.isInfixOf "line 1"
                renderedLogs `shouldSatisfy` BS8.isInfixOf "alice"
                renderedLogs `shouldSatisfy` BS8.isInfixOf "line 2"
                renderedLogs `shouldNotSatisfy` BS8.isInfixOf "secret"
                renderedLogs `shouldNotSatisfy` BS8.isInfixOf "hash"
                renderedLogs `shouldNotSatisfy` BS8.isInfixOf "extra"
                renderedLogs `shouldNotSatisfy` BS8.isInfixOf "raw-secret-without-separators"

withTempAuthFile :: BS.ByteString -> (FilePath -> IO a) -> IO a
withTempAuthFile contents action = bracket create cleanup (action . fst)
  where
    create = do
        (path, handle) <- openTempFile "." "hprox-auth-test"
        BS.hPut handle contents
        hClose handle
        return (path, ())

    cleanup (path, ()) = removeFile path

