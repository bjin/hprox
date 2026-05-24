-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.DoHSpec
  ( spec
  ) where

import Data.ByteString            qualified as BS
import Data.ByteString.Base64.URL qualified as Base64
import Data.ByteString.Lazy       qualified as LBS
import Data.IORef                 (IORef, newIORef, readIORef, writeIORef)
import Network.DNS                qualified as DNS
import Network.HTTP.Types         qualified as HT
import Network.Wai
import Network.Wai.Test

import Network.HProx.DoH

import Test.Hspec

spec :: Spec
spec =
  describe "dnsOverHTTPS" $ do
    it "handles secure GET /dns-query requests with unpadded URL-safe base64" $ do
      response <- runDoHRequest getDnsRequest
      simpleStatus response `shouldBe` HT.status200
      lookup "Content-Type" (simpleHeaders response) `shouldBe` Just "application/dns-message"
      decodedResponse response `shouldSatisfy` hasRequestIdentifier

    it "handles secure POST /dns-query requests with application/dns-message bodies" $ do
      response <- runDoHRequest postDnsRequest
      simpleStatus response `shouldBe` HT.status200
      lookup "Content-Type" (simpleHeaders response) `shouldBe` Just "application/dns-message"
      decodedResponse response `shouldSatisfy` hasRequestIdentifier

    it "returns the current text 400 response for malformed requests" $ do
      response <- runDoHRequest getDnsRequest { queryString = [("dns", Just "not-base64!")] }
      simpleStatus response `shouldBe` HT.status400
      lookup "Content-Type" (simpleHeaders response) `shouldBe` Just "text/plain"
      simpleBody response `shouldBe` "invalid dns-over-https request"

    it "rejects POST bodies beyond the current 4096-byte boundary" $ do
      response <- runDoHRequestWithBody postDnsRequest { requestBodyLength = KnownLength 4097 } (LBS.replicate 4097 0)
      simpleStatus response `shouldBe` HT.status400
      simpleBody response `shouldBe` "invalid dns-over-https request"

    it "accepts chunked POST bodies within the size boundary" $ do
      response <- runDoHRequestWithBody postDnsRequest { requestBodyLength = ChunkedBody } (LBS.fromStrict encodedQuery)
      simpleStatus response `shouldBe` HT.status200
      lookup "Content-Type" (simpleHeaders response) `shouldBe` Just "application/dns-message"
      decodedResponse response `shouldSatisfy` hasRequestIdentifier

    it "rejects chunked POST bodies beyond the size boundary" $ do
      response <- runDoHRequestWithBody postDnsRequest { requestBodyLength = ChunkedBody } (LBS.replicate 4097 0)
      simpleStatus response `shouldBe` HT.status400
      simpleBody response `shouldBe` "invalid dns-over-https request"

    it "returns 502 when the DNS resolver fails" $ do
      response <- runDoHRequestWithApplication resolverFailureApplication getDnsRequest ""
      simpleStatus response `shouldBe` HT.status502
      simpleBody response `shouldBe` "dns resolver failure"

    it "parses valid POST bodies split across multiple chunks" $ do
      chunks <- newIORef [BS.take 5 encodedQuery, BS.drop 5 encodedQuery]
      parsed <- parseDoHRequestWithBodyReader (popChunk chunks) postDnsRequest
      parsed `shouldBe` Just DoHRequest
        { dohIdentifier = requestIdentifier
        , dohQuestion = decodedQuestion
        }

    it "falls through outside secure /dns-query requests" $ do
      insecureResponse <- runDoHRequest getDnsRequest { isSecure = False }
      otherPathResponse <- runDoHRequest getDnsRequest { pathInfo = ["other"], rawPathInfo = "/other" }
      simpleStatus insecureResponse `shouldBe` fallbackStatus
      simpleBody insecureResponse `shouldBe` fallbackBody
      simpleStatus otherPathResponse `shouldBe` fallbackStatus
      simpleBody otherPathResponse `shouldBe` fallbackBody

runDoHRequest :: Request -> IO SResponse
runDoHRequest req = runDoHRequestWithBody req requestBody
  where
    requestBody
      | requestMethod req == "POST" = LBS.fromStrict encodedQuery
      | otherwise = ""

runDoHRequestWithBody :: Request -> LBS.ByteString -> IO SResponse
runDoHRequestWithBody req body = runSession (srequest $ SRequest req body) testApplication

runDoHRequestWithApplication :: Application -> Request -> LBS.ByteString -> IO SResponse
runDoHRequestWithApplication app req body = runSession (srequest $ SRequest req body) app

popChunk :: IORef [BS.ByteString] -> IO BS.ByteString
popChunk chunksRef = do
  chunks <- readIORef chunksRef
  case chunks of
    [] -> return ""
    chunk : rest -> do
      writeIORef chunksRef rest
      return chunk

testApplication :: Application
testApplication = dnsOverHTTPSWithLookup lookupResponse fallback

lookupResponse :: DNS.Question -> IO (Either DNS.DNSError DNS.DNSMessage)
lookupResponse lookupQuestion = return $ Right (DNS.makeResponse responseIdentifier lookupQuestion [])

resolverFailureApplication :: Application
resolverFailureApplication = dnsOverHTTPSWithLookup lookupFailure fallback

lookupFailure :: DNS.Question -> IO (Either DNS.DNSError DNS.DNSMessage)
lookupFailure _ = return $ Left (error "unused resolver error")

fallback :: Application
fallback _req respond = respond $ responseLBS fallbackStatus [("Content-Type", "text/plain")] fallbackBody

fallbackStatus :: HT.Status
fallbackStatus = HT.mkStatus 418 "fallback"

fallbackBody :: LBS.ByteString
fallbackBody = "fallback"

getDnsRequest :: Request
getDnsRequest = secureDnsRequest
  { requestMethod = "GET"
  , queryString = [("dns", Just (Base64.encodeUnpadded encodedQuery))]
  }

postDnsRequest :: Request
postDnsRequest = secureDnsRequest
  { requestMethod = "POST"
  , requestBodyLength = KnownLength (fromIntegral $ LBS.length requestBody)
  }
  where
    requestBody = LBS.fromStrict encodedQuery

secureDnsRequest :: Request
secureDnsRequest = defaultRequest
  { isSecure = True
  , pathInfo = ["dns-query"]
  , rawPathInfo = "/dns-query"
  }

encodedQuery :: BS.ByteString
encodedQuery = DNS.encode queryMessage

queryMessage :: DNS.DNSMessage
queryMessage = DNS.defaultQuery
  { DNS.header = (DNS.header DNS.defaultQuery) { DNS.identifier = requestIdentifier }
  , DNS.question = [question]
  }

question :: DNS.Question
question = DNS.Question
  { DNS.qname = "example.com"
  , DNS.qtype = DNS.A
  }

decodedQuestion :: DNS.Question
decodedQuestion = question { DNS.qname = "example.com." }

requestIdentifier :: DNS.Identifier
requestIdentifier = 0x1234

responseIdentifier :: DNS.Identifier
responseIdentifier = 0x9999

decodedResponse :: SResponse -> Either DNS.DNSError DNS.DNSMessage
decodedResponse = DNS.decode . LBS.toStrict . simpleBody

hasRequestIdentifier :: Either DNS.DNSError DNS.DNSMessage -> Bool
hasRequestIdentifier (Right DNS.DNSMessage{DNS.header = DNS.DNSHeader{DNS.identifier = ident}}) =
  ident == requestIdentifier
hasRequestIdentifier _ = False
