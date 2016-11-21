// Copyright (c) 2011-2013 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_QT_STARDELEGATE_H
#define SYSCOIN_QT_STARDELEGATE_H

#include <QStyledItemDelegate>

class StarDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    StarDelegate(QWidget *parent = 0) : QStyledItemDelegate(parent) {}

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const;
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const;
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const;
    void setEditorData(QWidget *editor, const QModelIndex &index) const;
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const;

private Q_SLOTS:
    void commitAndCloseEditor();
};

#endif // SYSCOIN_QT_STARDELEGATE_H
