{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Web.ConsumerData.Au.LambdaBank.Server where

{--
Notes: this is just moving the FakeServer from the types tests across for now.
We will split it apart and make it into a real server with config and a database
and not all in one file. Don't be too upset
that it looks heinous for now!
--}

import Web.ConsumerData.Au.Api.Types

import Control.Concurrent.STM.TVar (TVar, newTVarIO)
import Control.Monad.IO.Class   (liftIO)
import Control.Monad.Reader     (runReaderT)
import Network.Wai              (Application)
import Network.Wai.Handler.Warp (run)
import Servant.Server           (Handler)
import Servant.Server.Generic   (AsServerT)

import Web.ConsumerData.Au.LambdaBank.Alien.Servant.Server (genericServeT)
import Web.ConsumerData.Au.LambdaBank.LambdaModel          (runLambdaModelM)
import Web.ConsumerData.Au.LambdaBank.Server.Auth          (authServer)
import Web.ConsumerData.Au.LambdaBank.Server.Banking       (bankingServer)
import Web.ConsumerData.Au.LambdaBank.Server.Common        (commonServer)
import Web.ConsumerData.Au.LambdaBank.Server.Internal      (LambdaBankM)

routes :: Api (AsServerT LambdaBankM)
routes = Api
  { _common = commonServer
  , _banking = bankingServer
  , _auth = authServer
  }

app :: TVar Integer -> LinkQualifier -> Application
app tv lq = genericServeT runLambdaBankM routes
  where
    runLambdaBankM :: LambdaBankM a -> Handler a
    runLambdaBankM m =
      liftIO . runLambdaModelM tv . runReaderT m $ lq

runServer :: Int -> LinkQualifier -> IO ()
runServer port lq = do
  tv <- newTVarIO 0
  run port (app tv lq)
