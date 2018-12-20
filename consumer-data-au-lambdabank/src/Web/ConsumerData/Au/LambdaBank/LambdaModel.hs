{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeOperators         #-}

module Web.ConsumerData.Au.LambdaBank.LambdaModel where

import Control.Concurrent.STM.TVar (TVar, newTVarIO)
import Control.Monad.Free.Church   (F, foldF)
import Control.Monad.IO.Class      (MonadIO)
import Control.Monad.Reader        (MonadReader, ReaderT, runReaderT)

import Data.Coproduct                           ((:+:) (Inl, Inr))
import Web.ConsumerData.Au.LambdaBank.AuthModel (AuthModelF, runAuthModelF)
import Web.ConsumerData.Au.LambdaBank.Model     (ModelF, runModelF)

type RunLambdaModelM a = forall m. (MonadIO m, MonadReader (TVar Integer) m) => m a

class RunLambdaModelF f where
  runLambdaModelF :: f a -> RunLambdaModelM a

instance (RunLambdaModelF f, RunLambdaModelF g) => RunLambdaModelF (f :+: g) where
  runLambdaModelF = \case
    Inl f -> runLambdaModelF f
    Inr g -> runLambdaModelF g

instance RunLambdaModelF AuthModelF where
  runLambdaModelF = runAuthModelF

instance RunLambdaModelF ModelF where
  runLambdaModelF = runModelF

type LambdaModelM = F (AuthModelF :+: ModelF)

runLambdaModelM ::
  forall a.
  LambdaModelM a
  -> IO a
runLambdaModelM ma = do
  tv <- newTVarIO 0
  let
    na :: ReaderT (TVar Integer) IO a
    na = foldF runLambdaModelF ma
  runReaderT na tv