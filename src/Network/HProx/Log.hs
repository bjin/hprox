-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.Log
  ( LogLevel(..)
  , LogOutput(..)
  , LogStr
  , LogType'(..)
  , Logger
  , ToLogStr(..)
  , logLevelReader
  , logOutputType
  , parseLogOutput
  , withLogger
  ) where

import System.Log.FastLogger

-- | Logging level, default value is INFO
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
logLevelReader _       = Nothing

data LogOutput = LogOutputNone
               | LogOutputStdout
               | LogOutputStderr
               | LogOutputFile !FilePath
  deriving (Show, Eq)

parseLogOutput :: String -> LogOutput
parseLogOutput "none"   = LogOutputNone
parseLogOutput "stdout" = LogOutputStdout
parseLogOutput "stderr" = LogOutputStderr
parseLogOutput file     = LogOutputFile file

logOutputType :: LogOutput -> LogType' LogStr
logOutputType LogOutputNone        = LogNone
logOutputType LogOutputStdout      = LogStdout 4096
logOutputType LogOutputStderr      = LogStderr 4096
logOutputType (LogOutputFile file) = LogFileNoRotate file 4096

logWith :: TimedFastLogger -> LogLevel -> LogStr -> IO ()
logWith logger level logstr = logger (\time -> toLogStr time <> " [" <> toLogStr (show level) <> "] " <> logstr <> "\n")

type Logger = LogLevel -> LogStr -> IO ()
withLogger :: LogType -> LogLevel -> ((LogLevel -> LogStr -> IO ()) -> IO ()) -> IO ()
withLogger logType logLevel toRun = do
    timeCache <- newTimeCache "%Y/%m/%d %T %Z"
    withTimedFastLogger timeCache logType $ \timedLogger ->
        let logger level str
                | level < logLevel = return ()
                | otherwise        = logWith timedLogger level str
        in toRun logger
