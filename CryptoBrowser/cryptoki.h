#ifndef CRYPTOKI_H
#define CRYPTOKI_H

#include <includes\pkcs11.h>
#include <QLibrary>
#include <QTreeView>
#include <QStandardItemModel>
#include <QStandardItem>


class Cryptoki
{
    QLibrary library;
    CK_SESSION_HANDLE hSession;
    CK_SLOT_ID slotID;
    CK_FUNCTION_LIST_PTR pFunctionList;

public:
    Cryptoki();
    ~Cryptoki();
    void OpenSession(int islotID);
    void CloseSession();
    void GetSlotAndTokenInfo(QStandardItemModel* model);
};

#endif // CRYPTOKI_H
