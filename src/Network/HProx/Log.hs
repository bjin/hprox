-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

module Network.HProx.Log
  ( LogLevel (..)
  , LogStr
  , LogType' (..)
  , Logger
  , ToLogStr (..)
  , logLevelReader
  , pureLogger
  , withLogger
  ) where

import System.IO.Unsafe (unsafePerformIO)

import System.Log.FastLogger

data LogLevel = TRACE
              | DEBUG
              | INFO
              | WARN
              | ERROR
              | NONE
    deriving (Show, Eq, Ord)

logLevelReader :: String -> Maybe LogLevel
logLevelReader "trace" = Just TRACE
logLevelReader "debug" = Just DEBUG
logLevelReader "info"  = Just INFO
logLevelReader "warn"  = Just WARN
logLevelReader "error" = Just ERROR
logLevelReader "none"  = Just NONE
loglevelReader _       = Nothing

logWith :: TimedFastLogger -> LogLevel -> LogStr -> IO ()
logWith logger level logstr = logger (\time -> toLogStr time <> " [" <> toLogStr (show level) <> "] " <> logstr <> "\n")

type Logger = LogLevel -> LogStr -> IO ()

{-# NOINLINE pureLogger #-}
pureLogger :: Logger -> LogLevel -> LogStr -> a -> a
pureLogger logger level str a = unsafePerformIO $ logger level str >> return a

withLogger :: LogType -> LogLevel -> ((LogLevel -> LogStr -> IO ()) -> IO ()) -> IO ()
withLogger logType logLevel toRun = do
    timeCache <- newTimeCache "%Y/%m/%d %T %Z"
    withTimedFastLogger timeCache logType $ \timedLogger ->
        let logger level str
                | level < logLevel = return ()
                | otherwise        = logWith timedLogger level str
        in toRun logger
