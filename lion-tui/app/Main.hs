{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ImportQualifiedPost #-}
-- {-# LANGUAGE AllowAmbiguousTypes #-}

module Main where

import Control.Monad (void)
import Lens.Micro
import Lens.Micro.TH
import Lens.Micro.Mtl
import qualified Graphics.Vty as V
#if !(MIN_VERSION_base(4,11,0))
import Data.Semigroup ((<>))
#endif

import qualified Brick.Main as M
import qualified Brick.Types as T
import Brick.Widgets.Core
  ( (<+>)
  , vBox
  , hLimit
  , vLimit
  , str
  , visible
  , viewport
  , withDefAttr, strWrap, strWrapWith, withVScrollBars
  )
import qualified Brick.Widgets.Center as C
import qualified Brick.Widgets.Edit as E
import qualified Brick.AttrMap as A
import Brick.Util (on, fg)

import Lion.Rvfi (Rvfi(..), RvfiCsr, mkRvfi)
import Data.Text (Text)
import Brick.Widgets.Table
import GHC.TypeLits (KnownSymbol, symbolVal, KnownNat)
import Clash.NamedTypes
import Data.Data (Proxy(..))
import Clash.Prelude (Symbol)
import Text.Wrap
import Lion.Rvfi (RvfiCsr(..))
import Brick (ViewportType(..), VScrollBarOrientation (..), ViewportScroll, viewportScroll, (<=>))
import GHC.Word (Word32)
import Data.Vector.Mutable (IOVector)
import Data.Vector.Mutable qualified as MV

data Name = Edit
          | EditLines
          | RvfiView
          deriving (Ord, Show, Eq)

data St = St
  { _edit :: E.Editor String Name
  , _rvfi :: Rvfi
  , _memVec :: IOVector Word32
  }
makeLenses ''St

drawUI :: St -> [T.Widget Name]
drawUI st = [rvfi]
    where
        e = renderWithLineNumbers (st^.edit)
        ui = C.center . hLimit 50 . vLimit 10
        rvfi = withVScrollBars OnRight
             $ viewport RvfiView Vertical
             $ drawRvfi (_rvfi st)

drawRvfi :: Rvfi -> T.Widget Name
drawRvfi = drawRvfiTable

keyValTable :: Table n -> Table n
keyValTable =
   alignRight 0
  . alignLeft 1
  . rowBorders True
  . columnBorders True
  . surroundingBorder True

drawRvfiTable :: Rvfi -> T.Widget Name
drawRvfiTable Rvfi{..} = renderTable
  . keyValTable
  $ table
    [ drawRow @"valid"     52 _rvfiValid
    , drawRow @"order"     42 _rvfiOrder
    , drawRow @"insn"      52 _rvfiInsn
    , drawRow @"trap"      52 _rvfiTrap
    , drawRow @"halt"      52 _rvfiHalt
    , drawRow @"intr"      52 _rvfiIntr
    , drawRow @"mode"      52 _rvfiMode
    , drawRow @"ixl"       52 _rvfiIxl
    , drawRow @"rs1_addr"  52 _rvfiRs1Addr
    , drawRow @"rs2_addr"  52 _rvfiRs2Addr
    , drawRow @"rs1_rdata" 52 _rvfiRs1Data
    , drawRow @"rs2_rdata" 52 _rvfiRs2Data
    , drawRow @"rd_addr"   52 _rvfiRdAddr
    , drawRow @"rd_wdata"  52 _rvfiRdWData
    , drawRow @"pc_rdata"  52 _rvfiPcRData
    , drawRow @"pc_wdata"  52 _rvfiPcWData
    , drawRow @"mem_addr"  52 _rvfiMemAddr
    , drawRow @"mem_rmask" 52 _rvfiMemRMask
    , drawRow @"mem_wmask" 52 _rvfiMemWMask
    , drawRow @"mem_rdata" 52 _rvfiMemRData
    , drawRow @"mem_wdata" 52 _rvfiMemWData
    , drawRvfiCsr @"csr_minstret" _rvfiCsrMinstret
    , drawRvfiCsr @"csr_mcycle" _rvfiCsrMcycle
    , drawRvfiCsr @"csr_mscratch" _rvfiCsrMscratch
    , drawRvfiCsr @"csr_mstatus" _rvfiCsrMstatus
    , drawRvfiCsr @"csr_misa" _rvfiCsrMisa
    ]

drawRvfiCsr :: forall l n. (KnownSymbol l,KnownNat n) => RvfiCsr n -> [T.Widget Name]
drawRvfiCsr RvfiCsr{..} =
  [ str ""
  , str (symbolVal @l Proxy)
  <=> (renderTable
      . keyValTable
      $ table
        [ drawRow @"wdata" 42 _wdataCsr
        , drawRow @"rdata" 42 _rdataCsr
        , drawRow @"wmask" 42 _wmaskCsr
        , drawRow @"rmask" 42 _rmaskCsr
        ]
      )
  ]


newtype Named (name :: k) a = Named a

toNamed :: (l ::: v) -> Named l v
toNamed = Named

prefixWrapping :: WrapSettings
prefixWrapping = defaultWrapSettings
  { breakLongWords = True
  , fillStrategy = FillIndent 2}

drawRow :: forall l v n ll.
  (KnownSymbol l, Show v)
  => Int
  -> (ll ::: v)
  -> [T.Widget n]
drawRow w v =
  [ str (symbolVal @l (Proxy :: Proxy l))
  , hLimit w $ strWrapWith prefixWrapping (show v)
  ]


-- drawPair :: Show a => Text -> a -> (T.Widget Name, T.Widget Name)
-- drawPair l v = (txt l, )

-- | Given an editor, render the editor with line numbers to the left of
-- the editor.
--
-- This essentially exploits knowledge of how the editor is implemented:
-- we make a viewport containing line numbers that is just as high as
-- the editor, then request that the line number associated with the
-- editor's current line position be made visible, thus scrolling it
-- into view. This is slightly brittle, however, because it relies on
-- essentially keeping the line number viewport and the editor viewport
-- in the same vertical scrolling state; with direct scrolling requests
-- from EventM it is easily possible to put the two viewports into a
-- state where they do not have the same vertical scrolling offset. That
-- means that visibility requests made with 'visible' won't necessarily
-- have the same effect in each viewport in that case. So this is
-- only really usable in the case where you're sure that the editor's
-- viewport and the line number viewports will not be managed by direct
-- viewport operations in EventM. That's what I'd recommend anyway, but
-- still, this is an important caveat.
--
-- There's another important caveat here: this particular implementation
-- has @O(n)@ performance for editor height @n@ because we generate
-- the entire list of line numbers on each rendering depending on the
-- height of the editor. That means that for sufficiently large files,
-- it will get more expensive to render the line numbers. There is a way
-- around this problem, which is to take the approach that the @List@
-- implementation takes: only render a region of visible line numbers
-- around the currently-edited line that is just large enough to be
-- guaranteed to fill the viewport, then translate that so that it
-- appears at the right viewport offset, thus faking a viewport filled
-- with line numbers when in fact we'd only ever render at most @2 * K +
-- 1@ line numbers for a viewport height of @K@. That's more involved,
-- so I didn't do it here, but that would be the way to go for a Real
-- Application.
renderWithLineNumbers :: E.Editor String Name -> T.Widget Name
renderWithLineNumbers e =
    lineNumbersVp <+> editorVp
    where
        lineNumbersVp = hLimit (maxNumWidth + 1) $ viewport EditLines T.Vertical body
        editorVp = E.renderEditor (str . unlines) True e
        body = withDefAttr lineNumberAttr $ vBox numWidgets
        numWidgets = mkNumWidget <$> numbers
        mkNumWidget i = maybeVisible i $ str $ show i
        maybeVisible i
            | i == curLine + 1 =
                visible . withDefAttr  currentLineNumberAttr
            | otherwise =
                id
        numbers = [1..h]
        contents = E.getEditContents e
        h = length contents
        curLine = fst $ E.getCursorPosition e
        maxNumWidth = length $ show h

rvfiScroll :: ViewportScroll Name
rvfiScroll = viewportScroll RvfiView

appEvent :: T.BrickEvent Name e -> T.EventM Name St ()
appEvent (T.VtyEvent (V.EvKey V.KEsc [])) =
    M.halt
appEvent (T.VtyEvent (V.EvKey V.KDown []))   = M.vScrollBy rvfiScroll 1
appEvent (T.VtyEvent (V.EvKey V.KUp []))     = M.vScrollBy rvfiScroll (-1)
appEvent ev = do
    zoom edit $ E.handleEditorEvent ev

initialiseState :: Int -> IO St
initialiseState memlen = do
    v <- MV.replicate memlen 0
    pure $ St (E.editor Edit Nothing "") mkRvfi v

lineNumberAttr :: A.AttrName
lineNumberAttr = A.attrName "lineNumber"

currentLineNumberAttr :: A.AttrName
currentLineNumberAttr = lineNumberAttr <> A.attrName "current"

theMap :: A.AttrMap
theMap = A.attrMap V.defAttr
    [ (E.editAttr,              V.white `on` V.blue)
    , (E.editFocusedAttr,       V.black `on` V.yellow)
    , (lineNumberAttr,          fg V.cyan)
    , (currentLineNumberAttr,   V.defAttr `V.withStyle` V.bold)
    ]

theApp :: M.App St e Name
theApp =
    M.App { M.appDraw = drawUI
          , M.appChooseCursor = const $ M.showCursorNamed Edit
          , M.appHandleEvent = appEvent
          , M.appStartEvent = return ()
          , M.appAttrMap = const theMap
          }

main :: IO ()
main = do
    initialState <- initialiseState 1024
    void $ M.defaultMain theApp initialState