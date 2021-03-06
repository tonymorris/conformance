{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE RankNTypes      #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeOperators   #-}
module Web.ConsumerData.Au.Api.Types
  ( module Web.ConsumerData.Au.Api.Types
  , module Auth
  , module Banking
  , module Common
  , module CommonFieldTypes
  , module PhysicalAddress
  , module Request
  , module Response
  , module Data.Digit.Decimal
  , module Data.Vector.V5
  , module Data.Vector.V6
  ) where

import Control.Lens        (Getter, to)
import Data.Digit.Decimal  (DecDigit (..))
import Data.Proxy          (Proxy (..))
import GHC.Generics        (Generic)
import Servant.API         ((:>), Link)
import Servant.API.Generic
    ((:-), AsApi, ToServant, ToServantApi, fromServant, genericApi)
import Servant.Links       (AsLink, allFieldLinks)

import Data.Vector.V5
import Data.Vector.V6
import Web.ConsumerData.Au.Api.Types.Auth                  as Auth
import Web.ConsumerData.Au.Api.Types.Banking               as Banking
import Web.ConsumerData.Au.Api.Types.Common                as Common
import Web.ConsumerData.Au.Api.Types.Data.CommonFieldTypes as CommonFieldTypes
import Web.ConsumerData.Au.Api.Types.Data.PhysicalAddress  as PhysicalAddress
import Web.ConsumerData.Au.Api.Types.Request               as Request
import Web.ConsumerData.Au.Api.Types.Response              as Response

type CommonRoute r = r :- "common" :> ToServant CommonApi AsApi
type BankingRoute r = r :- "banking" :> ToServant BankingApi AsApi
type AuthRoute r = r :- "auth" :> ToServant AuthApi AsApi

data Api r = Api
  { _common  :: CommonRoute r
  , _banking :: BankingRoute r
  , _auth    :: AuthRoute r
  } deriving (Generic)

common :: Getter (Api r) (CommonRoute r)
common = to _common

banking :: Getter (Api r) (BankingRoute r)
banking = to _banking

auth :: Getter (Api r) (AuthRoute r)
auth = to _auth

api :: Proxy (ToServantApi Api)
api = genericApi (Proxy :: Proxy Api)

links :: Api (AsLink Link)
links = allFieldLinks

commonLinks :: Getter (Api (AsLink Link)) (CommonApi (AsLink Link))
commonLinks = common . to fromServant

bankingLinks :: Getter (Api (AsLink Link)) (BankingApi (AsLink Link))
bankingLinks = banking . to fromServant
