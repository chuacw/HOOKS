unit Hooktext;

interface

uses
  SysUtils, WinTypes, WinProcs, Messages, Classes, Graphics, Controls,
  Forms, Dialogs, Hooks, Gauges, StdCtrls, Menus, ExtCtrls;

type
  TForm1 = class(TForm)
    ListBox1: TListBox;
    MainMenu1: TMainMenu;
    Exit1: TMenuItem;
    Hook1: TMenuItem;
    TextOut1: TMenuItem;
    ExtTextOut1: TMenuItem;
    TabbedTextOut1: TMenuItem;
    ListBox2: TListBox;
    ListBox3: TListBox;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    DrawText1: TMenuItem;
    Timer1: TTimer;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure TextOut1Click(Sender: TObject);
    procedure ExtTextOut1Click(Sender: TObject);
    procedure TabbedTextOut1Click(Sender: TObject);
    procedure Exit1Click(Sender: TObject);
    procedure DrawText1Click(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  pExtTextOut,
  pTabbedTextOut,
  pTextOut,
  pDrawText: TFarProc;
  Form1: TForm1;
  npExtTextOut,
  npTabbedTextOut,
  npTextOut,
  npDrawText: TNPHookChild;
  gListBox1,
  gListBox2,
  gListBox3: TListBox;
  TempHeap, GlobalHeap: PChar;

function ExtTextOut(DC: HDC; X, Y: Integer; Options: Word;
  Rect: PRect; Str: PChar; Count: Word; Dx: PInteger): Bool;
 interrupt;  
function TabbedTextOut(DC: HDC; X, Y: Integer; Str: PChar; Count: Integer;
  TabPositions: Integer; var TabStopPositions; TabOrigin: Integer): LongInt; export;
function TextOut(DC: HDC; X, Y: Integer; Str: PChar; Count: Integer): Bool; export;

implementation
{$R *.DFM}
{$S-}

function ExtTextOut(DC: HDC; X, Y: Integer; Options: Word;
  Rect: PRect; Str: PChar; Count: Word; Dx: PInteger): Bool;
begin
 asm
  MOV AX, SEG npExtTextOut
  MOV DS, AX
 end;
 ProcUnhook(npExtTextOut);
 Result := WinProcs.ExtTextOut(DC, X, Y, Options, Rect, Str, Count, Dx);
 ProcHook(npExtTextOut);
{ TempHeap := StrECopy(TempHeap, Str); }
 asm popf end;
end;

function TabbedTextOut(DC: HDC; X, Y: Integer; Str: PChar; Count: Integer;
  TabPositions: Integer; var TabStopPositions; TabOrigin: Integer): LongInt;
begin
 ProcUnhook(npTabbedTextOut);
 if Assigned(gListBox2) then
  gListBox2.Items.Add(StrPas(Str));
 Result := WinProcs.TabbedTextOut(DC, X, Y, Str, Count, TabPositions,
                                  TabStopPositions, TabOrigin);
 ProcHook(npTabbedTextOut);
end;

function TextOut(DC: HDC; X, Y: Integer; Str: PChar; Count: Integer): Bool;
begin
 ProcUnhook(npTextOut);
 if Assigned(gListBox1) then
  gListBox1.Items.Add(StrPas(Str));
 Result := WinProcs.TextOut(DC, X, Y, Str, Count);
 ProcHook(npTextOut);
end;

function DrawText(DC: HDC; Str: PChar; Count: Integer; const Rect: TRect;
  Format: Word): Integer; export;
begin
 ProcUnhook(npDrawText);
 if Assigned(gListBox1) then
  gListBox1.Items.Add(StrPas(Str));
 Result := WinProcs.DrawText(DC, Str, Count, Rect, Format);
 ProcHook(npDrawText);
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
 npTextOut       := 0;
 npExtTextOut    := 0;
 npTabbedTextOut := 0;
 gListBox1 := ListBox1;
 gListBox2 := ListBox2;
 gListBox3 := ListBox3;
 GetMem(GlobalHeap, 32768);
 TempHeap := GlobalHeap;
 FillChar(TempHeap^, 32768, 0);
 pExtTextOut    := MakeProcInstance(@ExtTextOut, HInstance);
 pTabbedTextOut := MakeProcInstance(@TabbedTextOut, HInstance);
 pTextOut       := MakeProcInstance(@TextOut, HInstance);
 pDrawText      := MakeProcInstance(@DrawText, HInstance);
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
 if npTextOut<>0 then
  SetProcRelease(npTextOut);
 if npExtTextOut<>0 then
  SetProcRelease(npExtTextOut);
 if npTabbedTextOut<>0 then
  SetProcRelease(npTabbedTextOut);
 if npDrawText<>0 then
  SetProcRelease(npDrawText);
 FreeMem(GlobalHeap, 32768);
 FreeProcInstance(pTextOut);
 FreeProcInstance(pExtTextOut);
 FreeProcInstance(pTabbedTextOut);
 FreeProcInstance(pDrawText);
end;

procedure TForm1.TextOut1Click(Sender: TObject);
begin
 if TextOut1.Checked then
  begin
   SetProcRelease(npTextOut);
   npTextOut := 0;
   TextOut1.Checked := False;
   ListBox1.Visible := True;
  end else
  begin
   ListBox1.Visible := False;
   TextOut1.Checked := True;
   npTextOut       := SetProcAddress(@WinProcs.TextOut, pTextOut, True);
  end;
end;

procedure TForm1.ExtTextOut1Click(Sender: TObject);
var
 LocalBreak: Boolean;
begin
 if ExtTextOut1.Checked then
  begin
   SetProcRelease(npExtTextOut);
   npExtTextOut := 0;
   ExtTextOut1.Checked := False;
   LocalBreak := False;
   while TempHeap[0]<>#0 do
    begin
     ListBox3.Items.Add(StrPas(TempHeap));
     if LocalBreak then Break;
     TempHeap := StrEnd(TempHeap)+1;
    end;
   ListBox3.Visible := True;
  end else
  begin
   ListBox3.Visible := False;
   ExtTextOut1.Checked := True;
   npExtTextOut       := SetProcAddress(@WinProcs.ExtTextOut, pExtTextOut, True);
  end;
end;

procedure TForm1.TabbedTextOut1Click(Sender: TObject);
begin
 if TabbedTextOut1.Checked then
  begin
   SetProcRelease(npTabbedTextOut);
   npTabbedTextOut := 0;
   TabbedTextOut1.Checked := False;
   ListBox2.Visible := True;
  end else
  begin
   ListBox2.Visible := False;
   TabbedTextOut1.Checked := True;
   npTabbedTextOut        := SetProcAddress(@WinProcs.TabbedTextOut, pTabbedTextOut, True);
  end;
end;

procedure TForm1.DrawText1Click(Sender: TObject);
begin
 if DrawText1.Checked then
  begin
   SetProcRelease(npDrawText);
   npDrawText := 0;
   DrawText1.Checked := False;
   ListBox2.Visible := True;
  end else
  begin
   ListBox2.Visible := False;
   DrawText1.Checked := True;
   npDrawText        := SetProcAddress(@WinProcs.DrawText, pDrawText, True);
  end;
end;

procedure TForm1.Exit1Click(Sender: TObject);
begin
 Close;
end;

procedure TForm1.Timer1Timer(Sender: TObject);
begin
 Invalidate;
end;

label MyExtTextOut, Skip, Skip2;
begin
 DebugBreak;
 gListBox1 := nil;
 gListBox2 := nil;
 gListBox3 := nil;
 goto Skip;
 asm
  MyExtTextOut:
  MOV AX, SEG npExtTextOut;
  JMP ExtTextOut
  Skip:
  MOV WORD PTR PExtTextOut+2, OFFSET MyExtTextOut
  MOV WORD PTR PExtTextOut, SEG MyExtTextOut
 end;
end.
