-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

{-# LANGUAGE CPP                 #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.HProx.Platform.Unix
  ( PrivilegeDropPlan(..)
  , ResolvedGroup(..)
  , ResolvedUser(..)
  , dropRootPriviledge
  , installSighupHandler
  , planPrivilegeDrop
  ) where

import Control.Applicative
import Control.Monad
import Data.List           (nub, sort)

import Network.HProx.Log

#ifdef OS_UNIX
import Control.Exception    (SomeException, catch)
import System.Exit
import System.Posix.Process (exitImmediately)
import System.Posix.Signals (Handler(Catch), installHandler, sigHUP)
import System.Posix.User
#endif

type PrivilegeID = Integer

data ResolvedUser = ResolvedUser
    { resolvedUserName           :: String
    , resolvedUserID             :: PrivilegeID
    , resolvedUserPrimaryGroupID :: PrivilegeID
    }
  deriving (Eq, Show)

data ResolvedGroup = ResolvedGroup
    { resolvedGroupName    :: String
    , resolvedGroupID      :: PrivilegeID
    , resolvedGroupMembers :: [String]
    }
  deriving (Eq, Show)

data PrivilegeDropPlan = PrivilegeDropPlan
    { privilegeDropUserName            :: Maybe String
    , privilegeDropUserID              :: Maybe PrivilegeID
    , privilegeDropGroupName           :: Maybe String
    , privilegeDropGroupID             :: Maybe PrivilegeID
    , privilegeDropSupplementaryGroups :: [PrivilegeID]
    }
  deriving (Eq, Show)

planPrivilegeDrop :: Maybe ResolvedUser -> Maybe ResolvedGroup -> [ResolvedGroup] -> PrivilegeDropPlan
planPrivilegeDrop userEntry groupEntry allGroups = PrivilegeDropPlan
    { privilegeDropUserName            = resolvedUserName <$> userEntry
    , privilegeDropUserID              = resolvedUserID <$> userEntry
    , privilegeDropGroupName           = resolvedGroupName <$> groupEntry
    , privilegeDropGroupID             = finalGroupID
    , privilegeDropSupplementaryGroups = supplementaryGroups
    }
  where
    finalGroupID = resolvedGroupID <$> groupEntry <|> resolvedUserPrimaryGroupID <$> userEntry
    supplementaryGroups = case (resolvedUserName <$> userEntry, finalGroupID) of
        (Just name, Just primaryGroupID) ->
            nub $ primaryGroupID : [resolvedGroupID entry | entry <- allGroups, name `elem` resolvedGroupMembers entry]
        _otherwise                       -> []

#ifdef OS_UNIX
installSighupHandler :: IO () -> IO ()
installSighupHandler action = do
    _ <- installHandler sigHUP (Catch action) Nothing
    return ()

dropRootPriviledge :: Logger -> Maybe String -> Maybe String -> IO Bool
dropRootPriviledge _ Nothing Nothing = return False
dropRootPriviledge logger user groupName' = do
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
          let resolveUser entry = ResolvedUser (userName entry) (fromIntegral $ userID entry) (fromIntegral $ userGroupID entry)
              resolveGroup entry = ResolvedGroup (groupName entry) (fromIntegral $ groupID entry) (groupMembers entry)
          resolvedUser <- fmap resolveUser <$> mapM getUserEntryForName user
          resolvedGroup <- fmap resolveGroup <$> mapM getGroupEntryForName groupName'
          allGroups <- maybe (return []) (const $ map resolveGroup <$> getAllGroupEntries) resolvedUser
          let plan = planPrivilegeDrop resolvedUser resolvedGroup allGroups
          case privilegeDropUserName plan of
              Just userName' -> do
                  logger INFO $ "set supplementary groups for " <> toLogStr userName'
                  setGroups $ map fromIntegral $ privilegeDropSupplementaryGroups plan
              Nothing ->
                  forM_ (privilegeDropGroupID plan) $ \_ -> do
                      logger INFO "clear supplementary groups"
                      setGroups []
          forM_ (privilegeDropGroupID plan) $ \gid -> do
              logger INFO $ "setgid to " <> maybe (toLogStr $ show gid) toLogStr (privilegeDropGroupName plan)
              setGroupID $ fromIntegral gid
              verifyGroupID abort gid
          forM_ (privilegeDropUserID plan) $ \uid -> do
              logger INFO $ "setuid to " <> maybe (toLogStr $ show uid) toLogStr (privilegeDropUserName plan)
              setUserID $ fromIntegral uid
              verifyUserID abort uid
          verifySupplementaryGroups abort $ privilegeDropSupplementaryGroups plan
          logger DEBUG "testing setuid(0), verify that root priviledge can't be regranted"
          catch (setUserID 0) $ \(_ :: SomeException) -> logger DEBUG "setuid(0) failed as expected"
          changedUser <- getRealUserID
          when (changedUser == 0) $ abort "unable to drop root priviledge, aborting"
          return True

verifyUserID :: (LogStr -> IO ()) -> PrivilegeID -> IO ()
verifyUserID abort expectedUserID = do
    realUserID <- getRealUserID
    effectiveUserID <- getEffectiveUserID
    when (fromIntegral realUserID /= expectedUserID || fromIntegral effectiveUserID /= expectedUserID || realUserID == 0) $
        abort "failed to setuid, aborting"

verifyGroupID :: (LogStr -> IO ()) -> PrivilegeID -> IO ()
verifyGroupID abort expectedGroupID = do
    realGroupID <- getRealGroupID
    effectiveGroupID <- getEffectiveGroupID
    when (fromIntegral realGroupID /= expectedGroupID || fromIntegral effectiveGroupID /= expectedGroupID || realGroupID == 0) $
        abort "failed to setgid, aborting"

verifySupplementaryGroups :: (LogStr -> IO ()) -> [PrivilegeID] -> IO ()
verifySupplementaryGroups abort expectedGroups = do
    changedGroups <- map fromIntegral <$> getGroups
    when (sort (nub changedGroups) /= sort (nub expectedGroups)) $
        abort "failed to set supplementary groups, aborting"
#else
dropRootPriviledge :: Logger -> Maybe String -> Maybe String -> IO Bool
dropRootPriviledge _ _ _ = return False

installSighupHandler :: IO () -> IO ()
installSighupHandler _ = return ()
#endif
