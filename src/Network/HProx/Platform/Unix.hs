-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

{-# LANGUAGE CPP                 #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.HProx.Platform.Unix
  ( dropRootPriviledge
  ) where

import Control.Monad

import Network.HProx.Log

#ifdef OS_UNIX
import Control.Exception    (SomeException, catch)
import System.Exit
import System.Posix.Process (exitImmediately)
import System.Posix.User
#endif

#ifdef OS_UNIX
dropRootPriviledge :: Logger -> Maybe String -> Maybe String -> IO Bool
dropRootPriviledge _ Nothing Nothing = return False
dropRootPriviledge logger user group = do
    currentUser <- getRealUserID
    currentGroup <- getRealGroupID
    if currentUser /= 0 || currentGroup /= 0
      then do
        logger WARN $ "Unable to setuid/setgid without root priviledge" <>
                      ", userID=" <> toLogStr (show currentUser) <>
                      ", groupID=" <> toLogStr (show currentGroup)
        return False
      else do
        let abort msg = logger ERROR msg >> exitImmediately (ExitFailure 1)
        forM_ group $ \group' -> do
            logger INFO $ "setgid to " <> toLogStr group'
            getGroupEntryForName group' >>= setGroupID . groupID
            changedGroup <- getRealGroupID
            when (changedGroup == currentGroup) $ abort "failed to setgid, aborting"
        forM_ user $ \user' -> do
            logger INFO $ "setuid to " <> toLogStr user'
            getUserEntryForName user' >>= setUserID . userID
            changedUser <- getRealUserID
            when (changedUser == currentUser) $ abort "failed to setuid, aborting"
        logger DEBUG "testing setuid(0), verify that root priviledge can't be regranted"
        catch (setUserID 0) $ \(_ :: SomeException) -> logger DEBUG "setuid(0) failed as expected"
        changedUser <- getRealUserID
        when (changedUser == 0) $ abort "unable to drop root priviledge, aborting"
        return True
#else
dropRootPriviledge :: Logger -> Maybe String -> Maybe String -> IO Bool
dropRootPriviledge _ _ _ = return False
#endif
