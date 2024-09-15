

#include "cryptoki.h"

#include <QDebug>

Cryptoki::Cryptoki():
    library("softhsm2"),
    hSession(0),
    slotID(0)
{

    if (library.load())
    {
        qDebug() << "Library loaded successfully!";
    }
    else
    {
        qDebug() << "Failed to load library:" << library.errorString();
    }

    CK_RV rv = 0;

    // Get the list of Cryptographic functions
    using C_GetFunctionList_t = CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR);
    C_GetFunctionList_t C_GetFunctionList = (C_GetFunctionList_t)library.resolve("C_GetFunctionList");
    if (!C_GetFunctionList) {
        qDebug() << "C_GetFunctionList failed: " << rv;
        return;
    }

    // Assign the list of Cryptographic function to pointer
    rv = C_GetFunctionList(&pFunctionList);
    if (rv != CKR_OK) {
        qDebug() << "C_GetFunctionList failed: " << rv;
        return;
    }
}

Cryptoki::~Cryptoki()
{
    free(pFunctionList);
}

void Cryptoki::OpenSession(int islotID)
{
    CK_RV rv;

    // Initialize the PKCS#11 library
    rv = pFunctionList->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) {
        qDebug() << "C_Initialize failed: " << rv;
        return;
    }

    // Get the list of available slots
    CK_ULONG ulSlotCount;
    rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotCount);
    if (rv != CKR_OK) {
        qDebug() << "C_GetSlotList failed: " << rv;
        return;
    }

    CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    rv = pFunctionList->C_GetSlotList(CK_TRUE, pSlotList, &ulSlotCount);
    if (rv != CKR_OK) {
        qDebug() << "C_GetSlotList failed: " << rv;
        return;
    }

    // Get the desired Slot
    slotID = pSlotList[islotID];

    // Open a session
    rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
    if (rv != CKR_OK) {
        qDebug() << "C_OpenSession failed: " << rv;
        return;
    }

    // Login to the token
    rv = pFunctionList->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
    if (rv != CKR_OK) {
        qDebug() << "C_Login failed: " << rv;
        return;
    }
}

void Cryptoki::CloseSession()
{
    // Logout from the token
    CK_RV rv = pFunctionList->C_Logout(hSession);
    if (rv != CKR_OK) {
        qDebug() << "C_Logout failed: " << rv;
        return;
    }

    // Close the session
    rv = pFunctionList->C_CloseSession(hSession);
    if (rv != CKR_OK) {
        qDebug() << "C_CloseSession failed: " << rv;
        return;
    }

    // Finalize the PKCS#11 library
    rv = pFunctionList->C_Finalize(NULL_PTR);
    if (rv != CKR_OK) {
        qDebug() << "C_Finalize failed: " << rv;
        return;
    }
}

void Cryptoki::GetSlotAndTokenInfo(QStandardItemModel *model)
{

    model->setHorizontalHeaderLabels({"Slot Information"});

    CK_ULONG ulCount;
    CK_SLOT_ID_PTR pSlotList;
    CK_RV rv;

    rv = pFunctionList->C_GetSlotList(CK_FALSE, NULL_PTR, &ulCount);
    if ((rv == CKR_OK) && (ulCount > 0)) {
        pSlotList = (CK_SLOT_ID_PTR) malloc(ulCount*sizeof(CK_SLOT_ID));
        rv = pFunctionList->C_GetSlotList(CK_FALSE, pSlotList, &ulCount);
        if (rv != CKR_OK) {
            qDebug() << "C_GetSlotList failed: " << rv;
            return;
        }

        for (CK_ULONG i = 0; i < ulCount; ++i) {
            CK_SLOT_INFO slotInfo;
            rv = pFunctionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
            if (rv != CKR_OK) {
                qDebug() << "C_GetSlotList failed: " << rv;
                continue;
            }

            CK_TOKEN_INFO tokenInfo;
            rv = pFunctionList->C_GetTokenInfo(pSlotList[i], &tokenInfo);
            if (rv != CKR_OK) {
                qDebug() << "C_GetTokenInfo failed: " << rv;
                continue;
            }

            QStandardItem *item = new QStandardItem(QString("Slot %1").arg(i));
            item->appendRow(new QStandardItem(QString("Description: %1").arg(reinterpret_cast<char*>(slotInfo.slotDescription))));
            item->appendRow(new QStandardItem(QString("Label: %1").arg(reinterpret_cast<char*>(tokenInfo.label))));
            model->appendRow(item);
        }

    }
}
