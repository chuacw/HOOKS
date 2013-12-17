{ if the keyword INTERFACE is defined, this is the unit interface to
  the DLL, otherwise it is the DLL }
{$DEFINE INTERFACE}
{$IFDEF INTERFACE}
unit Hooks;
interface
uses WinTypes, WinProcs;
{$ELSE}
library CCWHooks;
uses WinTypes, WinProcs{, UndocWin};
{$D Procedural Hook v1.00 (C) Mar 1995 Chua Chee Wee}
{$ENDIF}
{$S-}
const
 { export indexes constants }
    eiSetProcAddress =1;
    eiSetProcRelease =2;
    eiProcHook       =3;
    eiProcUnhook     =4;

    eiGetFirstHMaster=5;
    eiGetNextHMaster =6;
    eiGetFirstHChild =7;
    eiGetNextHChild  =8;

    eiGetOrdFromAddr =9;
    eiGetNameFromOrd =10;

type
    TNPHookChild = Word;  { type near pointer to hook child is a word }
    TNPHookMaster = Word;
    PHookFuncByte = ^THookFuncByte;
    THookFuncByte = array[0..4] of Byte;

    PHookChild = ^THookChild;
    THookChild = record
     wSig: Word;
     Prev, Next: TNPHookChild; { offset to a THookChild within local heap }
     npHookMaster: TNPHookChild; { near ptr to Hook Master }
     cBytes: THookFuncByte;       { Bytes of hooked function }
     lpfnNewFunction: TFarProc;
    end;

    PHookMaster = ^THookMaster;
    THookMaster = record
     wSig: Word;
     Prev, Next: TNPHookChild;
     Head,                    { near ptr to a THookMaster within local heap }
     Tail: TNPHookChild;      { near ptr to tail of child structure }
     bExclusive: Bool;
     wCount, wUnhookCount: Word;
     wDataSel: THandle;
     lpfnHookedFunction: TFarProc;
    end;

{$IFDEF INTERFACE}

{ unit interface to routines to be declared }
    function SetProcAddress(lpfnOrigFunc, lpfnNewFunc: TFarProc;
                            Exclusive: Bool): TNPHookChild;
    function SetProcRelease(npHookChild: Word): Word;
    function ProcHook(npHookChild: Word): Word;
    function ProcUnhook(npHookChild: Word): Word;

    function GetFirstHMaster(lpHookMaster: PHookMaster): PHookMaster;
    function GetNextHMaster(lpHookMaster: PHookMaster): PHookMaster;
    function GetFirstHChild(lpHookMaster: PHookMaster;
                            lpHookChild: PHookChild): PHookChild;
    function GetNextHChild(lpHookChild: PHookChild): PHookChild;

    function GetOrdFromAddr(Module: THandle; Proc: TFarProc): Word;
    function GetNameFromOrd(Module: THandle; Ord: Word): string;

implementation
{uses UndocWin;}
const
 HOOKSDLL = 'HOOKS';
{ unit implementation pointing to an external DLL defining the actual
  run code }
    function SetProcAddress;  external HOOKSDLL index eiSetProcAddress;
    function SetProcRelease;  external HOOKSDLL index eiSetProcRelease;
    function ProcHook;        external HOOKSDLL index eiProcHook;
    function ProcUnhook;      external HOOKSDLL index eiProcUnhook;

    function GetFirstHMaster; external HOOKSDLL index eiGetFirstHMaster;
    function GetNextHMaster;  external HOOKSDLL index eiGetNextHMaster;
    function GetFirstHChild;  external HOOKSDLL index eiGetFirstHChild;
    function GetNextHChild;   external HOOKSDLL index eiGetNextHChild;

    function GetOrdFromAddr;  external HOOKSDLL index eiGetOrdFromAddr;
    function GetNameFromOrd;  external HOOKSDLL index eiGetNameFromOrd;

{$ELSE DLL implementation of procedural hooks}
var
 WinVer: Word;
 { internal details }
const
 NESignature = $454E;
 MasterSig = $464A; {'JF' reversed  i.e 'FJ'}
 ChildSig = $4643;  {'CF' reversed i.e 'FC'}
 JmpCode = $EA;

type
 PSegRec = ^TSegRec;
 TSegRec = record
  wSelOffset,           { offset to logical selector on disk }
  wSelLength,           { size of logical segment }
  wFlags,               { Flags }
  wSelSize: Word;       { Initial size of segment }
  wHandle: THandle;     { Handle/Selector to segment }
 end;

 { export ordinal bundle data structure }
 TNPNextBundle = Word;
 PBundle = ^TBundle;
 TBundle = record
  wFirstOrdinal,
  wLastOrdinal: Word;
  npNextBundle: TNPNextBundle;
 end;

 PEntry = ^TEntry;
 TEntry = record
  bySegmentType,        { segment type }
  byFlags,              { Flags }
  bySegmentNumber: Byte;{ Logical segment number }
  wOffset: Word;        { Offset of entry }
 end;

 { Module file information structure }
 PModuleFile = ^TModuleFile;
 TModuleFile = record
  byLength,
  byFlag: Byte;
  wUnknown: Word;
  wDate, wTime: Word;
  szFileName: array[0..0] of Char; { It's longer actually }
 end;

 PModuleTable = ^TModuleTable;
 TModuleTable = record
  Signature,
  LoadCount,
  PEntryTable,
  NextModuleSelector,
  OfsToSegEntry,
  LoadFileInfo,
  ModuleFlags,
  LogicalSegNum,
  HeapLocalSize,
  StackSize: Word;
  StartingCSIP, StartingSSSP: Longint;
  SegmentCount, wSegmentEntries,
  wModuleReferenceCount,
  wNonresidentNames,
  PSegmentTable,
  PResourceTable,
  PResidentNamesTable,
  PModuleRefTable,
  PImportedNamesTable,
  offsetToNonResidentNamesTable: Word;
 end;

 function LocalHeapSize: Word; far; external 'KERNEL' index 162;

 { Internally used functions }
 function CheckMasterRecord(npHookMaster: TNPHookMaster): Word;
 var
  lpHookMaster: PHookMaster;
 begin
  CheckMasterRecord := 0;
  lpHookMaster := Ptr(DSeg, npHookMaster);
  if (npHookMaster=0) or (lpHookMaster^.wSig<>MasterSig) then exit;
  CheckMasterRecord := 1;
 end;

 function CheckChildRecord(npHookChild: TNPHookChild): Word;
 var
  lpHookChild: PHookChild;
 begin
  CheckChildRecord := 0;
  lpHookChild := Ptr(DSeg, npHookChild);
  if (npHookChild=0) or (lpHookChild^.wSig<>ChildSig) then exit;
  CheckChildRecord := 1;
 end;

 { Return nonzero if successful otherwise zero }
 function CheckModulePtr(lpModTable: PModuleTable): Word;
 begin
  CheckModulePtr := 0;
  if (lpModTable=nil) or (lpModTable^.Signature<>NESignature) then exit;
  CheckModulePtr := 1;
 end;

 function WalkNameTable(var alpStr: string; wOrdi: Word): string;
 type
  PString = ^string;
 var
  lpStr: PChar absolute alpStr;
  lpLocalNameTable: PChar;
  byLength: Byte;
  wOrdinal: Word;
 begin
  WalkNameTable := '';
  lpLocalNameTable := lpStr;
  while lpLocalNameTable[0]<>#0 do
   begin
    byLength := Ord(lpLocalNameTable[0]);
    wOrdinal := PWord(lpLocalNameTable+byLength+1)^;
    if wOrdinal=wOrdi then
     begin
      WalkNameTable := PString(lpLocalNameTable)^;
      Break;
     end;
    lpLocalNameTable := lpLocalNameTable+3+byLength;
   end;
 end;

{ DLL's global variables/constant }
const
 npHookHead: TNPHookMaster = 0;
 npHookTail: TNPHookMaster = 0;

{ DLL exported routines }

    { Saves the first 5 bytes of the function referenced by npHookChild
      and replaces the 5 bytes with a far jump into the function we defined,
      lpfnNewFunc.
      Returns 0 if successful otherwise nonzero }
    function ProcHook(npHookChild: Word): Word; export;
    var
     npHookMast: TNPHookMaster;
     lpJmpPtr: PHookFuncByte;
    begin
     ProcHook := 1; { Assume failure }
     if CheckChildRecord(npHookChild)=0 then exit;
     npHookMast := PHookChild(Ptr(DSeg, npHookChild))^.npHookMaster;
{ wDataSel is the writable equivalent of the segment of the lpfnHookedFunction
  Therefore, lpJmpPtr will be equivalent to pointing to a writable portion
  of the first 5 bytes of the lpfnHookedFunction }

     with PHookMaster(Ptr(DSeg, npHookMast))^ do
      lpJmpPtr := Ptr(wDataSel, Ofs(lpfnHookedFunction^));
{ Save the first 5 bytes of the original function }
     Move(lpJmpPtr^[0], PHookChild(Ptr(DSeg, npHookChild))^.cBytes, SizeOf(THookFuncByte));
{ Change the first 5 bytes to point to the requested intercept routine }
     lpJmpPtr^[0] := JmpCode;
     Move(PHookChild(Ptr(DSeg, npHookChild))^.lpfnNewFunction, lpJmpPtr^[1], 4);
     Dec(PHookMaster(Ptr(DSeg, npHookMast))^.wUnhookCount);
     ProcHook := 0;
    end;

{ Restores the first 5 bytes of the function referenced by npHookChild,
  putting them back to the way they were before ProcHook got its hands on
  them!
  Returns 0 if successful, nonzero otherwise }
    function ProcUnhook(npHookChild: Word): Word; export;
    var
     npHookMast: TNPHookMaster;
     lpJmpPtr: PHookFuncByte;
    begin
     ProcUnhook := 1; { Assume failure }
     if CheckChildRecord(npHookChild)=0 then exit;
     npHookMast := PHookChild(Ptr(DSeg, npHookChild))^.npHookMaster;
     with PHookMaster(Ptr(DSeg, npHookMast))^ do
      lpJmpPtr := Ptr(wDataSel, Ofs(lpfnHookedFunction^));
     { Restore the 5 bytes to their original }
     Move(PHookChild(Ptr(DSeg, npHookChild))^.cBytes, lpJmpPtr^, 5);
     Inc(PHookMaster(Ptr(DSeg, npHookMast))^.wUnhookCount);
     ProcUnhook := 0;
    end;

    { This function handles all of the linked list management, checks to
      see if the procedure has been hooked before, and sets up the
      hook to our function.
      Returns - A near pointer to the NPHookChild of our function or 0
                upon failure }
    function SetProcAddress (const lpfnOrigFunc, lpfnNewFunc: TFarProc;
                            Exclusive: Bool): TNPHookChild; export;
    var
     npHookMast: TNPHookMaster;
     npHookChild: TNPHookChild;
     wCodeSel: THandle;
    label ReleaseChildExit;
    begin
     SetProcAddress := 0;
     npHookMast := npHookHead;
     npHookChild := LocalAlloc(LPtr, SizeOf(THookChild));
     if npHookChild=0 then exit;
     while npHookMast<>0 do
      begin
       if lpfnOrigFunc = PHookMaster(Ptr(DSeg, npHookMast))^.lpfnHookedFunction then
        Break;
       npHookMast := PHookMaster(Ptr(DSeg, npHookMast))^.Next;
      end;
{ if we got to the end of the master list without finding an entry }
     if npHookMast=0 then
      begin
       { Check to see if someone already hooked the function }
       if PByte(lpfnOrigFunc)^=JmpCode then
        begin ReleaseChildExit:
         LocalFree(npHookChild); { Free the child record }
         exit;
        end;
       npHookMast := LocalAlloc(LPtr, SizeOf(THookMaster));
       if npHookMast=0 then goto ReleaseChildExit;
       with PHookMaster(Ptr(DSeg, npHookMast))^ do
        begin
         lpfnHookedFunction := lpfnOrigFunc;
         wCount := 0; { No childs }
         wUnhookCount := 0;
         bExclusive := Exclusive;
         wSig := MasterSig;
         Prev := npHookTail;
         if Prev<>0 then PHookMaster(Ptr(DSeg, Prev))^.Next := npHookMast;
         Next := 0;
         Head := 0;
         Tail := 0;
        end;
       npHookTail := npHookMast;
       if npHookHead=0 then npHookHead := npHookMast;
       wCodeSel := Seg(lpfnOrigFunc^);
       GlobalFix(wCodeSel);
       PHookMaster(Ptr(DSeg, npHookMast))^.wDataSel := AllocCStoDSAlias(wCodeSel);
      end else
      with PHookMaster(Ptr(DSeg, npHookMast))^ do
       if bExclusive or Exclusive or (wUnhookCount>0) then
        goto ReleaseChildExit;
     { At this point, we are done with npHookMast. It is set up in the linked
       list and is pointing to the Master record of the function that we want
       to hook. We will now start setting up the child record
       (allocated above) by hooking it to the end of the child linked list
       and assigning its values }
     with PHookChild(Ptr(DSeg, npHookChild))^ do
      begin
       Prev := PHookMaster(Ptr(DSeg, npHookMast))^.Tail;
       Next := 0;
       if Prev<>0 then
         PHookChild(Ptr(DSeg, Prev))^.Next := npHookChild;
      end;
     with PHookMaster(Ptr(DSeg, npHookMast))^ do
      begin
       if Head=0 then Head := npHookChild;
       Tail := npHookChild;
       Inc(wCount);
      end;
     with PHookChild(Ptr(DSeg, npHookChild))^ do
      begin
       npHookMaster := npHookMast;
       wSig := ChildSig;
       lpfnNewFunction := lpfnNewFunc;
      end;
     Inc(PHookMaster(Ptr(DSeg, npHookMast))^.wUnhookCount);
     ProcHook(npHookChild);
     SetProcAddress := npHookChild;
    end;

    { Permanently unhooks the function referenced by npHookChild and
      glues the remaining structures together }
    { Any return value of nonzero indicates failure }
    function SetProcRelease(npHookChild: Word): Word; export;
    var
     npHookMast: TNPHookMaster;
     wCodeSel: THandle;
    begin
     SetProcRelease := 1; { Assume failure }
     if CheckChildRecord(npHookChild)=0 then exit;
     npHookMast := PHookChild(Ptr(DSeg, npHookChild))^.npHookMaster;
     if PHookMaster(Ptr(DSeg, npHookMast))^.wUnhookCount>0 then exit;
     with PHookChild(Ptr(DSeg, npHookChild))^ do
      begin
       if Prev<>0 then
        PHookChild(Ptr(DSeg, Prev))^.Next := Next else
        PHookMaster(Ptr(DSeg, npHookMast))^.Head := Next;
       if Next<>0 then
        begin
         PHookChild(Ptr(DSeg, Next))^.Prev := Prev;
         Move(cBytes, PHookChild(Ptr(DSeg, Next))^.cBytes, SizeOf(cBytes));
        end else
        begin
         PHookMaster(Ptr(DSeg, npHookMast))^.Tail := Prev;
         ProcUnhook(npHookChild);
         Dec(PHookMaster(Ptr(DSeg, npHookMast))^.wUnhookCount);
        end;
      end; { with }
     Dec(PHookMaster(Ptr(DSeg, npHookMast))^.wCount);
     FillChar(PHookChild(Ptr(DSeg, npHookChild))^, SizeOf(THookChild), 0);
     LocalFree(npHookChild);
     with PHookMaster(Ptr(DSeg, npHookMast))^ do
      begin
       if (Head=0) and (Tail=0) then
        begin
         if Prev<>0 then
          PHookMaster(Ptr(DSeg, Prev))^.Next := Next else
          npHookHead := Next;
         if Next<>0 then
          PHookMaster(Ptr(DSeg, Next))^.Prev := Prev else
          npHookTail := Prev;
        end;
       FreeSelector(wDataSel);
       wCodeSel := Seg(lpfnHookedFunction^);
       GlobalUnfix(wCodeSel);
      end;
     FillChar(PHookMaster(Ptr(DSeg, npHookMast))^, SizeOf(THookMaster), 0);
     LocalFree(npHookMast);
     SetProcRelease := 0;
    end;





    function GetFirstHMaster(lpHookMaster: PHookMaster): PHookMaster; export;
    begin
     GetFirstHMaster := nil;
     if CheckMasterRecord(npHookHead)<>0 then
      Move(PHookMaster(Ptr(DSeg, npHookHead))^, lpHookMaster^, SizeOf(THookMaster)) else
      exit;
     GetFirstHMaster := Ptr(DSeg, npHookHead);
    end;

    function GetNextHMaster(lpHookMaster: PHookMaster): PHookMaster; export;
    var
     npHookMast: TNPHookMaster;
    begin
     GetNextHMaster := nil;
     if CheckMasterRecord(Ofs(lpHookMaster^))=0 then exit;
     npHookMast := lpHookMaster^.Next;
     if CheckMasterRecord(npHookMast)<>0 then
      Move(PHookMaster(Ptr(DSeg, npHookMast))^, lpHookMaster^, SizeOf(THookMaster)) else
      exit;
     GetNextHMaster := Ptr(DSeg, npHookMast);
    end;

    function GetFirstHChild(lpHookMaster: PHookMaster;
                            lpHookChild: PHookChild): PHookChild; export;
    var
     npHookMast: TNPHookMaster;
     npHookChild: TNPHookChild;
    begin
     GetFirstHChild := nil;
     npHookMast := Ofs(lpHookMaster^);
     if CheckMasterRecord(npHookMast)=0 then exit;
     npHookChild := lpHookMaster^.Head;
     if CheckChildRecord(npHookChild)<>0 then
      Move(PHookChild(Ptr(DSeg, npHookChild))^, lpHookChild^, SizeOf(THookChild)) else
      exit;
     GetFirstHChild := Ptr(DSeg, npHookChild);
    end;

    function GetNextHChild(lpHookChild: PHookChild): PHookChild; export;
    var
     npHookChild: TNPHookChild;
    begin
     GetNextHChild := nil;
     if CheckChildRecord(Ofs(lpHookChild^))=0 then exit;
     npHookChild := lpHookChild^.Next;
     if CheckChildRecord(npHookChild)<>0 then
      Move(PHookChild(Ptr(DSeg, npHookChild))^, lpHookChild^, SizeOf(THookChild)) else
      exit;
     GetNextHChild := Ptr(DSeg, npHookChild);
    end;


    function HandleToSelector(Handle: THandle): THandle;
    begin
     Result := Handle;
     if WinVer = $30A then
      Result := Result or 1 else
     if WinVer < $30A then
      if Result and $0002 = $0002 then
       Result := Result-1;
    end;

    { Search for the ordinal number of an exported routine of a loaded
      Windows module via it's module handle and the routine's address }
    function GetOrdFromAddr(Module: THandle; lpfnFuncPtr: TFarProc): Word; export;
    var
     lpModTable: PModuleTable;
     lpSegRec: PSegRec;
     lpBundle: PBundle;
     lpEntry: PEntry;
     wSegNum, wOrdinal: Word;
     Found: Boolean;
    begin
     GetOrdFromAddr := 0;
     lpModTable := Ptr(HandleToSelector(Module), 0);
     if CheckModulePtr(lpModTable)=0 then exit;
     lpSegRec := Ptr(Seg(lpModTable^), lpModTable^.PSegmentTable);
     { Get logical segment number from Module Table. Step thru all segment
       entries until we reach the end or find a match. }
     for wSegNum := 1 to lpModTable^.wSegmentEntries do
      begin
       Found := HandleToSelector(lpSegRec^.wHandle)=Seg(lpfnFuncPtr);
       if Found then Break;
      end;
     if not Found then exit;
     Found := False;
     lpBundle := Ptr(Seg(lpModTable^), lpModTable^.PEntryTable);
     while Seg(lpBundle^)<>0 do
      begin
       lpEntry := Ptr(Seg(lpBundle^), Ofs(lpBundle^)+SizeOf(TBundle)+1);
       for wOrdinal := lpBundle^.wFirstOrdinal+1 to
                       lpBundle^.wLastOrdinal do
        begin
         if lpEntry^.bySegmentNumber=wSegNum then
          Found := lpEntry^.wOffset=Ofs(lpfnFuncPtr^);
         if Found then Break;
        end;
       if Found then Break;
       lpBundle := Ptr(Seg(lpModTable^), lpBundle^.npNextBundle);
       if not Found then exit;
       GetOrdFromAddr := wOrdinal;
      end;
    end;

    function GetNameFromOrd(Module: THandle; wOrdinal: Word): string; export;
    type
     PString=^string;
    var
     lpModTable: PModuleTable;
     lpModFile: PModuleFile;
     lpNameTab: PString;
     lpszStr: string;
     HFile: THandle;
    begin
     GetNameFromOrd := '';
     lpModTable := Ptr(HandleToSelector(Module), 0);
     if CheckModulePtr(lpModTable)=0 then exit;
     lpNameTab := Ptr(Seg(lpModTable^), lpModTable^.PResidentNamesTable);
     lpszStr := WalkNameTable(lpNameTab^, wOrdinal);
     if lpszStr='' then
      begin
       lpNameTab := GlobalAllocPtr(GHND, lpModTable^.wNonResidentNames);
       if lpNameTab=nil then exit;
       lpModFile := Ptr(Seg(lpModTable^), lpModTable^.LoadFileInfo);
       HFile := _lopen(lpModFile^.szFileName, of_READ);
       if HFile>0 then { Assume lesser than 0 is error, since HFile_Error's }
        begin          { value is not known }
         _llseek(HFile, lpModTable^.offsetToNonResidentNamesTable, 0);
         _lread(HFile, PChar(lpNameTab), lpModTable^.wNonResidentNames);
         _lclose(HFile);
         lpszStr := WalkNameTable(lpNameTab^, wOrdinal);
        end;
       GlobalFreePtr(lpNameTab);
      end;
     GetNameFromOrd := lpszStr;
    end;

{ DLL routine exports }
 exports
    SetProcAddress  index eiSetProcAddress  name '1',
    SetProcRelease  index eiSetProcRelease  name '2',
    ProcHook        index eiProcHook        name '3',
    ProcUnhook      index eiProcUnhook      name '4',

    GetFirstHMaster index eiGetFirstHMaster name '5',
    GetNextHMaster  index eiGetNextHMaster  name '6',
    GetFirstHChild  index eiGetFirstHChild  name '7',
    GetNextHChild   index eiGetNextHChild   name '8',

    GetOrdFromAddr  index eiGetOrdFromAddr  name '9',
    GetNameFromOrd  index eiGetNameFromOrd  name '0';

begin
 if LocalHeapSize>0 then
  UnlockData(0);
 WinVer := Swap(LoWord(GetVersion));
{$ENDIF DLL implementation}

end.
