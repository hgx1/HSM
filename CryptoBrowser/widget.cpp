#include "widget.h"
#include "ui_widget.h"

#include <QWidget>
#include <QVBoxLayout>


Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
    , crypt(new Cryptoki())
{
    ui->setupUi(this);
    QList<QTreeView*> listtreeView = findChildren<QTreeView*>("treeView", Qt::FindDirectChildrenOnly);
    QTreeView* treeView = listtreeView.at(0);
    QStandardItemModel* model = new QStandardItemModel();
    crypt->OpenSession(0);
    crypt->GetSlotAndTokenInfo(model);
    treeView->setModel(model);
    treeView->show();
    crypt->CloseSession();

}

Widget::~Widget()
{
    delete ui;
    delete crypt;
}

