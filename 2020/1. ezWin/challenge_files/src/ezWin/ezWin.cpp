#include <iostream>
#include <vector>
#include <Windows.h>
#include <assert.h>
#include <tchar.h>
#include <cstdio>
#include <string.h>
#include <stdio.h>
#include <winnt.h>
#include <stdlib.h>
#include <io.h>

using namespace std;

#define MAX_INPUT_SIZE 1024

class Note {
public:
    string* content;
    uint64_t epoch;
    uint64_t referenceNumber;

    Note(string* content, uint64_t epoch, uint64_t referenceNumber) {
        this->content = content;
        this->epoch = epoch;
        this->referenceNumber = referenceNumber;
    }

    virtual void Print() {
        printf("Note %llu (%llu):\n", referenceNumber, epoch);
        printf("Contents: %s\n", content->data());
    }
};

vector<Note*> g_notes;
string c_emptyStr("");
uint64_t g_debug = 0;

uint64_t GetLong(const char* msg) {
    uint64_t n;

    printf(msg);
    scanf_s("%llu", &n);

    return n;
}

void PrintHeader() {
    puts("                __      __.__        ");
    puts("  ____ ________/  \\    /  \\__| ____  ");
    puts("_/ __ \\\\___   /\\   \\/\\/   /  |/    \\ ");
    puts("\\  ___/ /    /  \\        /|  |   |  \\");
    puts(" \\___  >_____ \\  \\__/\\  / |__|___|  /");
    puts("     \\/      \\/       \\/          \\/ ");
    puts("");
}

void PrintOptions() {
    puts("");
    puts("=====Options====");
    puts("0. Print Options");
    puts("1. Create Note");
    puts("2. Edit Note");
    puts("3. Print Note");
    puts("4. Filter Note");
    puts("================");
    puts("");
}

void CreateNote() {
    static string tmpStr(MAX_INPUT_SIZE, '\0');
    uint64_t epoch, referenceNumber;
    int n;

    puts("====Create Note====");

    referenceNumber = GetLong("Note reference number: ");
    epoch = GetLong("Epoch time: ");

    printf("Note contents: ");
    n = _read(0, &tmpStr[0], MAX_INPUT_SIZE - 1);
    if (n < 0)
        n = 0;
    if (n > 0 && tmpStr[n - 1ll] == 10) 
        tmpStr[--n] = 0;

    string* content = n < 1 ? &c_emptyStr : new string(tmpStr, 0, n);
    Note* note = new Note(content, epoch, referenceNumber);
    g_notes.push_back(note);
}

void EditNote() {
    static string tmpStr(1024, '\0');
    uint64_t epoch, referenceNumber;
    int n;

    puts("====Edit Note====");
    referenceNumber = GetLong("Note reference number to edit: ");

    for (auto* note : g_notes) {
        if (note->referenceNumber == referenceNumber) {
            //the note integrity verification code is removed
            
            referenceNumber = GetLong("New reference number: ");
            epoch = GetLong("New epoch time: ");

            printf("New content to add: ");
            n = _read(0, &tmpStr[0], MAX_INPUT_SIZE - 1);
            if (n < 0)
                n = 0;
            if (n > 0 && tmpStr[n - 1ll] == 10) 
                tmpStr[--n] = 0;

            uint64_t mode = GetLong("Content replacement mode: ");

            note->referenceNumber = referenceNumber;
            note->epoch = epoch;

            if (mode == 0)
                note->content->replace(0, n, tmpStr, 0, n);
            else
                note->content->append(tmpStr, 0, n);

            break;
        }
    }
}

void FilterNote() {
    uint64_t referenceNumber;

    puts("====Filter Note====");
    referenceNumber = GetLong("Note reference number: ");

    for (auto* note : g_notes) {
        if (note->referenceNumber == referenceNumber && note->content->find("xxx") != string::npos) {
            printf("Filtered [#%llu] [%llu] [%s]\n", note->referenceNumber, note->epoch, note->content->data());
            delete note->content;
            break;
        }
    }
}

#define DATA_SIZE 0x80
void PrintNote() {
    uint64_t referenceNumber;
    uint8_t old[DATA_SIZE];
    Note* tempNote;

    puts("====Print Note====");

    memcpy(old, &g_notes, DATA_SIZE);

    referenceNumber = GetLong("Note reference number: ");

    for (int i = 0; i < g_notes.size(); i++) {
        if (g_notes[i]->referenceNumber == referenceNumber) {
            tempNote = g_notes[i];
            memset(&g_notes, 0, DATA_SIZE);
            tempNote->Print();
            memcpy(&g_notes, old, DATA_SIZE);
        }
    }

    if (g_debug) {
        system("echo DEBUG MODE");
        //printf("Reference reference number: %p\n", &referenceNumber);
    }
}

void __declspec(noinline) GetOption() {
    uint64_t choice;

    PrintOptions();
    choice = GetLong("choice> ");
    puts("");

    switch (choice) {
    case 1: CreateNote(); break;
    case 2: EditNote(); break;
    case 3: PrintNote(); break;
    case 4: FilterNote(); break;
    default:PrintOptions(); break;
    }
}

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    PrintHeader();
    do {
        GetOption();
    } while (1);

    return 0;
}