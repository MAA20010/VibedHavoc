#ifndef HAVOC_ONLINEOPERATORS_H
#define HAVOC_ONLINEOPERATORS_H

#include <global.hpp>

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QLabel>
#include <QTimer>
#include <QDateTime>

class HavocNamespace::UserInterface::SmallWidgets::OnlineOperators : public QWidget
{
    Q_OBJECT

public:
    QWidget*        OnlineOperatorsWidget;
    QVBoxLayout*    layoutMain;
    QTextEdit*      operatorConsole;

    OnlineOperators();
    void setupUi( QWidget* widget );
    void AppendText( const QString& Time, const QString& text );
    void updateOperatorDisplay();
    void updateTabTitle();
    int getConnectedCount() const;
    
    // Real-time event handlers from Packager
    void onUserConnected( QString username, QString timestamp );
    void onUserDisconnected( QString username, QString timestamp );

private:
    void setupStyling();
    
    // Track connected operators count
    QStringList connectedOperators;
};

#endif // HAVOC_ONLINEOPERATORS_H
