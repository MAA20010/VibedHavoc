#ifndef HAVOC_CHATWIDGET_H
#define HAVOC_CHATWIDGET_H

#include <global.hpp>
#include <QLineEdit>
#include <QTextEdit>
#include <QKeyEvent>

// Custom input widget that handles Enter vs Shift+Enter
class ChatInputEdit : public QTextEdit
{
    Q_OBJECT

public:
    explicit ChatInputEdit(QWidget* parent = nullptr) : QTextEdit(parent) {
        // Make it look like a single-line input initially
        setMaximumHeight(60);
        setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    }

protected:
    void keyPressEvent(QKeyEvent* event) override {
        // Enter without modifiers = send message
        if (event->key() == Qt::Key_Return && event->modifiers() == Qt::NoModifier) {
            emit returnPressed();
            event->accept();
            return;
        }
        // Shift+Enter = new line (default behavior)
        QTextEdit::keyPressEvent(event);
    }

signals:
    void returnPressed();
};

class HavocNamespace::UserInterface::Widgets::Chat : public QWidget
{
    Q_OBJECT
    
    QGridLayout*    gridLayout      = nullptr;
    ChatInputEdit*  lineEdit        = nullptr;

public:
    QTextEdit*      EventLogText    = nullptr;
    QWidget*        ChatWidget      = nullptr;
    QString         TeamserverName  = nullptr;

    void setupUi( QWidget* widget );
    void AppendText( const QString& Time, const QString& text ) const;

    void AddUserMessage( const QString Time, QString User, QString text ) const;

public slots:
    void AppendFromInput();

};

#endif
