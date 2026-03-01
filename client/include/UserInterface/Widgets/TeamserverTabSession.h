#ifndef HAVOC_TEAMSERVERTABSESSION_H
#define HAVOC_TEAMSERVERTABSESSION_H

#include <global.hpp>
#include <QStackedWidget>
#include <QSplitter>

#include <UserInterface/Widgets/LootWidget.h>
#include <UserInterface/Widgets/ServerLootWidget.h>
#include <UserInterface/Widgets/SessionGraph.hpp>
#include <UserInterface/Widgets/NetworkDiagram.hpp>
#include <UserInterface/Widgets/Teamserver.hpp>
#include <UserInterface/Widgets/Store.hpp>
#include <UserInterface/Widgets/OnlineOperators.h>

#include <UserInterface/Dialogs/Payload.hpp>

using namespace HavocNamespace;

class HavocNamespace::UserInterface::Widgets::TeamserverTabSession : public QWidget
{
    typedef struct
    {
        UserInterface::SmallWidgets::EventViewer* EventViewer;
        UserInterface::SmallWidgets::OnlineOperators* OnlineOperators;
    } SmallAppWidgets_t;

public:
    QGridLayout* gridLayout              = {};
    QGridLayout* gridLayout_2            = {};
    QWidget*     layoutWidget            = {};
    QSplitter*   splitter_TopBot         = {};
    QSplitter*   splitter_SessionAndTabs = {};
    QVBoxLayout* verticalLayout          = {};
    QTabWidget*  tabWidget               = {};
    QTabWidget*  tabWidgetSmall          = {};

public:
    Widgets::Chat*                    TeamserverChat         = {};
    class Teamserver*                 Teamserver             = {};
    class Store*                      Store                  = {};
    Widgets::SessionTable*            SessionTableWidget     = {};
    GraphWidget*                      SessionGraphWidget     = {};
    NetworkDiagramManager*            NetworkDiagram         = {};
    Widgets::ListenersTable*          ListenerTableWidget    = {};
    Widgets::PythonScriptInterpreter* PythonScriptWidget     = {};
    Widgets::ScriptManager*           ScriptManagerWidget    = {};
    Payload*                          PayloadDialog          = {};
    class LootWidget*                 LootWidget             = {};
    class ServerLootWidget*           ServerLootWidget       = {};
    QStackedWidget*                   MainViewWidget         = {};
    QWidget*                          SessionTablePage       = {};
    HavocSpace::DBManager*            dbManager           = {};
    QString                           TeamserverName      = {};
    QWidget*                          PageWidget          = {};
    SmallAppWidgets_t*                SmallAppWidgets     = {};

    void setupUi( QWidget* Page, QString TeamserverName );
    void NewBottomTab( QWidget* TabWidget, const std::string& TitleName, QString IconPath = "" ) const;
    void NewWidgetTab( QWidget* TabWidget, const std::string& TitleName ) const;

protected slots:
    void handleDemonContextMenu( const QPoint& pos );
    void removeTabSmall( int ) const;

private:
    // Helper methods to reduce code duplication and improve performance
    Util::SessionItem* findSessionById(const QString& sessionId);
    int findTableRowBySessionId(const QString& sessionId);
    QColor getSessionColor(const QString& colorName);
    void setRowColors(int row, const QColor& bgColor, const QColor& fgColor);
};

#endif
