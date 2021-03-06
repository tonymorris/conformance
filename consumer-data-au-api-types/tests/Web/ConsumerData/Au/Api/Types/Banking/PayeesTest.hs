{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE TypeApplications  #-}

module Web.ConsumerData.Au.Api.Types.Banking.PayeesTest where

import Control.Lens

import Data.Functor.Identity (Identity)
import Data.Tagged           (Tagged)
import Test.Tasty            (TestTree)
import Text.URI.QQ           (uri)
import Waargonaut.Decode     (Decoder)
import Waargonaut.Encode     (Encoder)
import Waargonaut.Generic    (mkDecoder, mkEncoder, untag)
import WaargoRoundTrip       (roundTripTest)

import Web.ConsumerData.Au.Api.Types
import Web.ConsumerData.Au.Api.Types.LinkTestHelpers
    (linkTest, paginatedLinkTest)
import Web.ConsumerData.Au.Api.Types.PrismTestHelpers (testEnumPrismTripping)
import Web.ConsumerData.Au.Api.Types.Tag

test_payeesLinks :: [TestTree]
test_payeesLinks =
  [ paginatedLinkTest "Get Payees no params"
    ((links^.bankingLinks.bankingPayeesLinks.payeesGet) Nothing) [uri|http://localhost/banking/payees|]
  , paginatedLinkTest "Get Payees all params"
    ((links^.bankingLinks.bankingPayeesLinks.payeesGet) (Just International)) [uri|http://localhost/banking/payees?type=INTERNATIONAL|]
  , linkTest "Get Payee Detail"
    (links^.bankingLinks.bankingPayeesLinks.payeesByIdGet.to ($ PayeeId "123")) [uri|http://localhost/banking/payees/123|]
  ]

test_roundTripEnum :: [TestTree]
test_roundTripEnum =
  [ testEnumPrismTripping "PayeeType" _PayeeType
  ]

test_roundTripPayees :: TestTree
test_roundTripPayees = roundTripTest
  (untag (mkDecoder :: (Tagged OB (Decoder Identity (PaginatedResponse Payees)))))
  (untag (mkEncoder :: (Tagged OB (Encoder Identity (PaginatedResponse Payees)))))
  "PayeesRoundTrip"
  "tests/Web/ConsumerData/Au/Api/Types/Banking/PayeesTest/payees.golden.json"

test_roundTripPayeeDetail :: TestTree
test_roundTripPayeeDetail = roundTripTest
  (untag (mkDecoder :: (Tagged OB (Decoder Identity (StandardResponse PayeeDetail)))))
  (untag (mkEncoder :: (Tagged OB (Encoder Identity (StandardResponse PayeeDetail)))))
  "PayeeDetailRoundTrip"
  "tests/Web/ConsumerData/Au/Api/Types/Banking/PayeesTest/payeedetail.golden.json"

test_roundSubPayeeDetail :: [TestTree]
test_roundSubPayeeDetail =
  [ roundTripTest
    domesticPayeeDecoder
    domesticPayeeEncoder
    " DomesticPayeeRoundTrip"
    "tests/Web/ConsumerData/Au/Api/Types/Banking/PayeesTest/domesticPayee.json"
  , roundTripTest
    domesticPayeeAccountDecoder
    domesticPayeeAccountEncoder
    "  DomesticPayeeAccountRoundTrip"
    "tests/Web/ConsumerData/Au/Api/Types/Banking/PayeesTest/domesticPayeeAccount.json"
  , roundTripTest
    domesticPayeeCardDecoder
    domesticPayeeCardEncoder
    "  DomesticPayeeCardRoundTrip"
    "tests/Web/ConsumerData/Au/Api/Types/Banking/PayeesTest/domesticPayeeCard.json"
  , roundTripTest
    domesticPayeePayIdDecoder
    domesticPayeePayIdEncoder
    "  DomesticPayeePayIdRoundTrip"
    "tests/Web/ConsumerData/Au/Api/Types/Banking/PayeesTest/domesticPayeePayId.json"
  , roundTripTest
    internationalPayeeDecoder
    internationalPayeeEncoder
    " InternationalPayeeRoundTrip"
    "tests/Web/ConsumerData/Au/Api/Types/Banking/PayeesTest/internationalPayee.json"
  , roundTripTest
    billerPayeeDecoder
    billerPayeeEncoder
    " BillerPayeeRoundTrip"
    "tests/Web/ConsumerData/Au/Api/Types/Banking/PayeesTest/billerPayee.json"
  ]
