{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}

module Web.ConsumerData.Au.Api.Types.Banking.Common.ProductDetail where

import           Control.Lens               (Prism', prism, ( # ))
import           Data.Functor.Contravariant ((>$<))
import           Data.Text                  (Text)
import           Text.URI                   (URI)
import           Waargonaut.Decode          (Decoder)
import qualified Waargonaut.Decode          as D
import qualified Waargonaut.Decode.Error    as D
import           Waargonaut.Encode          (Encoder)
import qualified Waargonaut.Encode          as E
import           Waargonaut.Generic         (JsonDecode (..), JsonEncode (..))

import           Waargonaut.Helpers         (atKeyOptional', maybeOrAbsentE)
import Web.ConsumerData.Au.Api.Types.Response
    (uriDecoder, uriEncoder)
import Web.ConsumerData.Au.Api.Types.Tag

import Web.ConsumerData.Au.Api.Types.Banking.Common.Products
    (Product, productDecoder, productFields)
import Web.ConsumerData.Au.Api.Types.Banking.ProductAccountComponents.Product.Constraint
    (ProductConstraints, productConstraintsDecoder, productConstraintsEncoder)
import Web.ConsumerData.Au.Api.Types.Banking.ProductAccountComponents.Product.DepositRate
    (ProductDepositRates, productDepositRatesDecoder,
    productDepositRatesEncoder)
import Web.ConsumerData.Au.Api.Types.Banking.ProductAccountComponents.Product.Eligibility
    (ProductEligibilities, productEligibilitiesDecoder,
    productEligibilitiesEncoder)
import Web.ConsumerData.Au.Api.Types.Banking.ProductAccountComponents.Product.Feature
    (ProductFeatures, productFeaturesDecoder, productFeaturesEncoder)
import Web.ConsumerData.Au.Api.Types.Banking.ProductAccountComponents.Product.Fee
    (ProductFees, productFeesDecoder, productFeesEncoder)
import Web.ConsumerData.Au.Api.Types.Banking.ProductAccountComponents.Product.LendingRate
    (ProductLendingRates, productLendingRatesDecoder,
    productLendingRatesEncoder)


-- | ProductDetail <https://consumerdatastandardsaustralia.github.io/standards/?swagger#tocBankingCommonSchemas CDR AU v0.1.0 ProductDetail>
data ProductDetail = ProductDetail
  { _productDetailProduct       :: Maybe Product
  , _productDetailBundles       :: Maybe ProductBundles -- ^ An array of bundles that this product participates in. Each bundle is described by free form information but also by a list of product IDs of the other products that are included in the bundle. It is assumed that the current product is included in the bundle also
  , _productDetailFeatures      :: Maybe ProductFeatures -- ^ Array of features available for the product
  , _productDetailConstraints   :: Maybe ProductConstraints -- ^ Constraints on the application for or operation of the product such as minimum balances or limit thresholds
  , _productDetailEligibility   :: Maybe ProductEligibilities -- ^ Eligibility criteria for the product
  , _productDetailFees          :: Maybe ProductFees -- ^ Fees and charges applicable for the product
  , _productDetailDepositRates  :: Maybe ProductDepositRates -- ^ Interest rates available for deposits
  , _productDetailLendingRates  :: Maybe ProductLendingRates -- ^ Interest rates charged against lending balances
  , _productDetailRepaymentType :: Maybe ProductRepaymentType -- ^ For lending style products what are the options for repayments that are available. If absent (and relevant) defaults to PRINCIPAL_AND_INTEREST
  } deriving (Eq, Show)

productDetailDecoder :: Monad f => Decoder f ProductDetail
productDetailDecoder =
  ProductDetail
    <$> (D.maybeOrNull productDecoder)
    <*> atKeyOptional' "bundles" productBundlesDecoder
    <*> atKeyOptional' "features" productFeaturesDecoder
    <*> atKeyOptional' "constraints" productConstraintsDecoder
    <*> atKeyOptional' "eligibility" productEligibilitiesDecoder
    <*> atKeyOptional' "fees" productFeesDecoder
    <*> atKeyOptional' "depositRates" productDepositRatesDecoder
    <*> atKeyOptional' "lendingRates" productLendingRatesDecoder
    <*> atKeyOptional' "repaymentType" productRepaymentTypeDecoder

instance JsonDecode OB ProductDetail where
  mkDecoder = tagOb productDetailDecoder

instance JsonEncode OB ProductDetail where
  mkEncoder = tagOb productDetailEncoder

productDetailEncoder :: Applicative f => Encoder f ProductDetail
productDetailEncoder = E.mapLikeObj $ \pd ->
  maybe id productFields (_productDetailProduct pd) .
  maybeOrAbsentE "bundles" productBundlesEncoder (_productDetailBundles pd) .
  maybeOrAbsentE "features" productFeaturesEncoder (_productDetailFeatures pd) .
  maybeOrAbsentE "constraints" productConstraintsEncoder (_productDetailConstraints pd) .
  maybeOrAbsentE "eligibility" productEligibilitiesEncoder (_productDetailEligibility pd) .
  maybeOrAbsentE "fees" productFeesEncoder (_productDetailFees pd) .
  maybeOrAbsentE "depositRates" productDepositRatesEncoder (_productDetailDepositRates pd) .
  maybeOrAbsentE "lendingRates" productLendingRatesEncoder (_productDetailLendingRates pd) .
  maybeOrAbsentE "repaymentType" productRepaymentTypeEncoder (_productDetailRepaymentType pd)


newtype ProductBundles =
  ProductBundles { getProductBundles :: [ProductBundle] }
  deriving (Eq, Show)

productBundlesDecoder :: Monad f => Decoder f ProductBundles
productBundlesDecoder = ProductBundles <$> D.list productBundleDecoder

productBundlesEncoder :: Applicative f => Encoder f ProductBundles
productBundlesEncoder = getProductBundles >$< E.list productBundleEncoder

instance JsonDecode OB ProductBundles where
  mkDecoder = tagOb productBundlesDecoder

instance JsonEncode OB ProductBundles where
  mkEncoder = tagOb productBundlesEncoder


data ProductBundle = ProductBundle
  { _productBundleName              :: Text -- ^ Name of the bundle.
  , _productBundleDescription       :: Text -- ^ Description of the bundle.
  , _productBundleAdditionalInfoUri :: Maybe URI -- ^ Link to a web page with more information on the bundle criteria and benefits
  , _productBundleProductIds        :: [Text] -- ^ Array of product IDs for products included in the bundle.
  } deriving (Eq, Show)

productBundleDecoder :: Monad f => Decoder f ProductBundle
productBundleDecoder =
  ProductBundle
    <$> D.atKey "name" D.text
    <*> D.atKey "description" D.text
    <*> atKeyOptional' "applicationUri" uriDecoder
    <*> D.atKey "productIds" (D.list D.text)

instance JsonDecode OB ProductBundle where
  mkDecoder = tagOb productBundleDecoder

productBundleEncoder :: Applicative f => Encoder f ProductBundle
productBundleEncoder = E.mapLikeObj $ \p ->
  E.atKey' "name" E.text (_productBundleName p) .
  E.atKey' "description" E.text (_productBundleDescription p) .
  maybeOrAbsentE "applicationUri" uriEncoder (_productBundleAdditionalInfoUri p) .
  E.atKey' "productIds" (E.list E.text) (_productBundleProductIds p)

instance JsonEncode OB ProductBundle where
  mkEncoder = tagOb productBundleEncoder


-- | ProductRepaymentType <https://consumerdatastandardsaustralia.github.io/standards/?swagger#schemaproductcategory CDR AU v0.1.0 ProductCategory>
data ProductRepaymentType =
    PRepaymentTypeInterestOnly -- ^ "INTEREST_ONLY"
  | PRepaymentTypePrincipalAndInterest -- ^ "PRINCIPAL_AND_INTEREST"
  | PRepaymentTypeNegotiable -- ^ "NEGOTIABLE"
  deriving (Bounded, Enum, Eq, Ord, Show)

productRepaymentTypeText ::
  Prism' Text ProductRepaymentType
productRepaymentTypeText =
  prism (\case
          PRepaymentTypeInterestOnly -> "INTEREST_ONLY"
          PRepaymentTypePrincipalAndInterest -> "PRINCIPAL_AND_INTEREST"
          PRepaymentTypeNegotiable -> "NEGOTIABLE"
      )
      (\case
          "INTEREST_ONLY" -> Right PRepaymentTypeInterestOnly
          "PRINCIPAL_AND_INTEREST" -> Right PRepaymentTypePrincipalAndInterest
          "NEGOTIABLE"-> Right PRepaymentTypeNegotiable
          t -> Left t
      )

productRepaymentTypeDecoder :: Monad m => Decoder m  ProductRepaymentType
productRepaymentTypeDecoder = D.prismDOrFail
  (D._ConversionFailure # "Not a valid product repayment type")
  productRepaymentTypeText
  D.text

productRepaymentTypeEncoder :: Applicative f => Encoder f ProductRepaymentType
productRepaymentTypeEncoder =
  E.prismE productRepaymentTypeText E.text
