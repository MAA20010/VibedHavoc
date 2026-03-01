#include <global.hpp>

#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <UserInterface/Widgets/SessionTable.hpp>
#include <UserInterface/Widgets/SessionGraph.hpp>
#include <UserInterface/Widgets/NetworkDiagram.hpp>
#include <UserInterface/Widgets/DemonInteracted.h>
#include <UserInterface/Widgets/ProcessList.hpp>
#include <UserInterface/Widgets/Chat.hpp>
#include <UserInterface/Widgets/LootWidget.h>
#include <UserInterface/Widgets/FileBrowser.hpp>

#include <UserInterface/SmallWidgets/EventViewer.hpp>
#include <UserInterface/Widgets/OnlineOperators.h>

#include <Util/ColorText.h>
#include <Havoc/Packager.hpp>
#include <Havoc/Connector.hpp>

#include <QFile>
#include <QToolButton>
#include <QHeaderView>
#include <QByteArray>
#include <QKeyEvent>
#include <QShortcut>
#include <algorithm>

using namespace UserInterface::Widgets;

void HavocNamespace::UserInterface::Widgets::TeamserverTabSession::setupUi( QWidget* Page, QString TeamserverName )
{
    TeamserverName = TeamserverName;
    PageWidget = Page;

    SmallAppWidgets = new SmallAppWidgets_t;
    SmallAppWidgets->EventViewer = new UserInterface::SmallWidgets::EventViewer;
    SmallAppWidgets->EventViewer->setupUi( new QWidget );
    SmallAppWidgets->EventViewer->AppendText( CurrentDateTime(), "Havoc Framework [Version: " + QString( Version.c_str() ) + "] [CodeName: " + QString( CodeName.c_str() ) + "]" );

    SmallAppWidgets->OnlineOperators = new HavocNamespace::UserInterface::SmallWidgets::OnlineOperators;
    SmallAppWidgets->OnlineOperators->setupUi( new QWidget );

    auto MenuStyle = QString(
        "QMenu {"
        "    background-color: #282a36;"
        "    color: #f8f8f2;"
        "    border: 1px solid #44475a;"
        "}"
        "QMenu::separator {"
        "    background: #44475a;"
        "}"
        "QMenu::item:selected {"
        "    background: #44475a;"
        "}"
        "QAction {"
        "    background-color: #282a36;"
        "    color: #f8f8f2;"
        "}"
    );

    gridLayout = new QGridLayout(PageWidget);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    gridLayout->setContentsMargins(0, 0, 0, 0);

    splitter_TopBot = new QSplitter(PageWidget);
    splitter_TopBot->setOrientation(Qt::Vertical);
    splitter_TopBot->setContentsMargins(0, 0, 0, 0);

    layoutWidget = new QWidget( splitter_TopBot );

    verticalLayout  = new QVBoxLayout( layoutWidget );
    verticalLayout->setContentsMargins( 3, 3, 3, 3 );

    MainViewWidget   = new QStackedWidget( );
    SessionTablePage = new QWidget( );

    gridLayout_2 = new QGridLayout( SessionTablePage );
    gridLayout_2->setObjectName( QString::fromUtf8( "gridLayout_2" ) );
    gridLayout_2->setContentsMargins( 0, 0, 0, 0 );

    splitter_SessionAndTabs = new QSplitter( layoutWidget );
    splitter_SessionAndTabs->setOrientation( Qt::Horizontal );

    SessionTableWidget = new HavocNamespace::UserInterface::Widgets::SessionTable;
    SessionTableWidget->setupUi( new QTableWidget(), TeamserverName );
    SessionTableWidget->setFocusPolicy( Qt::NoFocus );

    SessionGraphWidget = new GraphWidget( MainViewWidget );

    // Session Table and Graph only
    MainViewWidget->addWidget( SessionTableWidget->SessionTableWidget );
    MainViewWidget->addWidget( SessionGraphWidget );
    MainViewWidget->setCurrentIndex( 0 );
    
    // Network Diagram is initialized as nullptr, created on demand as separate window
    NetworkDiagram = nullptr;

    splitter_SessionAndTabs->addWidget( MainViewWidget );

    tabWidgetSmall = new QTabWidget( splitter_SessionAndTabs );
    tabWidgetSmall->setObjectName( QString::fromUtf8( "tabWidgetSmall" ) );
    tabWidgetSmall->setMovable( false );

    splitter_SessionAndTabs->addWidget( tabWidgetSmall );

    gridLayout_2->addWidget( splitter_SessionAndTabs, 0, 0, 1, 1 );

    verticalLayout->addWidget( SessionTablePage );

    splitter_TopBot->addWidget( layoutWidget );
    tabWidget = new QTabWidget( splitter_TopBot );
    tabWidget->setObjectName( QString::fromUtf8( "tabWidget" ) );
    splitter_TopBot->addWidget( tabWidget );

    gridLayout->addWidget(splitter_TopBot, 0, 0, 1, 1);

    TeamserverChat = new UserInterface::Widgets::Chat;
    TeamserverChat->TeamserverName = HavocX::Teamserver.Name;
    TeamserverChat->setupUi( new QWidget );

    NewBottomTab( TeamserverChat->ChatWidget, "Teamserver Chat", ":/icons/users" );
    tabWidget->setCurrentIndex( 0 );
    tabWidget->setMovable( false );

    LootWidget = new ::LootWidget;

    NewWidgetTab( SmallAppWidgets->EventViewer->EventViewer, "Event Viewer" );
    NewWidgetTab( SmallAppWidgets->OnlineOperators->OnlineOperatorsWidget, QString("Online Operators (👤%1)").arg(SmallAppWidgets->OnlineOperators->getConnectedCount()).toStdString() );

    connect( SessionTableWidget->SessionTableWidget, &QTableWidget::customContextMenuRequested, this, &TeamserverTabSession::handleDemonContextMenu );
    connect( tabWidget->tabBar(), &QTabBar::tabCloseRequested, this, [&]( int index )
    {
        if ( index == -1 )
            return;

        tabWidget->removeTab( index );

        if ( tabWidget->count() == 0 )
        {
            splitter_TopBot->setSizes( QList<int>() << 0 );
            splitter_TopBot->setStyleSheet( "QSplitter::handle {  image: url(images/notExists.png); }" );
        }
        else if ( tabWidget->count() == 1 )
        {
            tabWidget->setMovable( false );
        }
    } );

    connect( tabWidgetSmall->tabBar(), &QTabBar::tabCloseRequested, this, &TeamserverTabSession::removeTabSmall );

    connect( SessionTableWidget->SessionTableWidget, &QTableWidget::doubleClicked, this, [&]( const QModelIndex &index ) {
        auto SessionID = SessionTableWidget->SessionTableWidget->item( index.row(), 0 )->text();

        for ( const auto& Session : HavocX::Teamserver.Sessions )
        {
            if ( Session.Name.compare( SessionID ) == 0 )
            {
                auto tabName = "[" + Session.Name + "] " + Session.User + "/" + Session.Computer;
                for ( int i = 0 ; i < HavocX::Teamserver.TabSession->tabWidget->count(); i++ )
                {
                    if ( HavocX::Teamserver.TabSession->tabWidget->tabText( i ) == tabName )
                    {
                        HavocX::Teamserver.TabSession->tabWidget->setCurrentIndex( i );
                        return;
                    }
                }

                HavocX::Teamserver.TabSession->NewBottomTab( Session.InteractedWidget->DemonInteractedWidget, tabName.toStdString() );
                Session.InteractedWidget->lineEdit->setFocus();
            }
        }
    } );
}

void UserInterface::Widgets::TeamserverTabSession::handleDemonContextMenu( const QPoint &pos )
{
    if ( ! SessionTableWidget->SessionTableWidget->itemAt( pos ) ) {
        return;
    }

    auto MenuStyle  = QString(
        "QMenu {"
        "    background-color: #282a36;"
        "    color: #f8f8f2;"
        "    border: 1px solid #44475a;"
        "}"
        "QMenu::separator {"
        "    background: #44475a;"
        "}"
        "QMenu::item:selected {"
        "    background: #44475a;"
        "}"
        "QAction {"
        "    background-color: #282a36;"
        "    color: #f8f8f2;"
        "}"
    );

    auto SessionID = SessionTableWidget->SessionTableWidget->item( SessionTableWidget->SessionTableWidget->currentRow(), 0 )->text();
    auto Agent     = findSessionById(SessionID);

    if (!Agent) {
        return; // Session not found
    }

    auto separator  = new QAction();
    auto separator2 = new QAction();
    auto separator3 = new QAction();
    auto separator4 = new QAction();

    separator->setSeparator( true );
    separator2->setSeparator( true );
    separator3->setSeparator( true );
    separator4->setSeparator( true );

    auto SessionMenu     = QMenu();
    auto SessionExplorer = QMenu( "Explorer" );
    auto ExitMenu        = QMenu( "Exit" );
    auto ColorMenu       = QMenu( "Color" );

    ColorMenu.addAction( "Reset" );
    ColorMenu.addAction( "Red" );
    ColorMenu.addAction( "Blue" );
    ColorMenu.addAction( "Yellow" );
    ColorMenu.addAction( "Pink" );
    ColorMenu.addAction( "Green" );
    ColorMenu.addAction( "Purple" );
    ColorMenu.addAction( "Orange" );

    ColorMenu.setStyleSheet( MenuStyle );

    SessionExplorer.addAction( "Process List" );
    SessionExplorer.addAction( "File Explorer" );
    SessionExplorer.setStyleSheet( MenuStyle );

    ExitMenu.addAction( "Thread" );
    ExitMenu.addAction( "Process" );
    ExitMenu.setStyleSheet( MenuStyle );

    // Check if multiple rows are selected for bulk operations
    auto selectedRows = SessionTableWidget->SessionTableWidget->selectionModel()->selectedRows();
    bool multipleSelected = selectedRows.count() > 1;

    SessionMenu.addAction( "Interact" );
    SessionMenu.addAction( separator );

    if ( IsValidDemonMagic(Agent->MagicValue) )
    {
        SessionMenu.addAction( SessionExplorer.menuAction() );
        SessionMenu.addAction( separator2 );
    }

    // Add bulk operations if multiple sessions selected
    if ( multipleSelected )
    {
        SessionMenu.addAction( "Mark Selected as Dead" );
        SessionMenu.addAction( "Mark Selected as Alive" );
        SessionMenu.addAction( separator4 );
    }
    else
    {
        // Single session operations
        if ( Agent->Marked.compare( "Dead" ) != 0 )
            SessionMenu.addAction( "Mark as Dead" );
        else
            SessionMenu.addAction( "Mark as Alive" );
    }

    SessionMenu.addAction( ColorMenu.menuAction() );

    SessionMenu.addAction( "Export" );
    SessionMenu.addAction( separator3 );
    
    // Add bulk remove and remove all dead options
    if ( multipleSelected )
        SessionMenu.addAction( "Remove Selected" );
    else
        SessionMenu.addAction( "Remove" );
    
    SessionMenu.addAction( "Remove All Dead Sessions" );

    if ( IsValidDemonMagic(Agent->MagicValue) )
    {
        SessionMenu.addAction( ExitMenu.menuAction() );
    }
    else
    {
        SessionMenu.addAction( "Exit" );
    }

    SessionMenu.setStyleSheet( MenuStyle );

    auto *action = SessionMenu.exec( SessionTableWidget->SessionTableWidget->horizontalHeader()->viewport()->mapToGlobal( pos ) );

    if ( action )
    {
        for ( auto& Session : HavocX::Teamserver.Sessions )
        {
            // TODO: make that on Session receive
            if ( Session.InteractedWidget == nullptr )
            {
                Session.InteractedWidget                 = new UserInterface::Widgets::DemonInteracted;
                Session.InteractedWidget->SessionInfo    = Session;
                Session.InteractedWidget->TeamserverName = HavocX::Teamserver.Name;
                Session.InteractedWidget->setupUi( new QWidget );
            }

            if ( Session.Name.compare( SessionID ) == 0 )
            {
                if ( action->text().compare( "Interact" ) == 0 )
                {
                    auto tabName = "[" + Session.Name + "] " + Session.User + "/" + Session.Computer;
                    for ( int i = 0 ; i < HavocX::Teamserver.TabSession->tabWidget->count(); i++ )
                    {
                        if ( HavocX::Teamserver.TabSession->tabWidget->tabText( i ) == tabName )
                        {
                            HavocX::Teamserver.TabSession->tabWidget->setCurrentIndex( i );
                            return;
                        }
                    }

                    HavocX::Teamserver.TabSession->NewBottomTab( Session.InteractedWidget->DemonInteractedWidget, tabName.toStdString() );
                    Session.InteractedWidget->lineEdit->setFocus();
                }
                else if ( action->text().compare( "Red" ) == 0 || action->text().compare( "Blue" ) == 0 || action->text().compare( "Pink" ) == 0 || action->text().compare( "Yellow" ) == 0 || action->text().compare( "Green" ) == 0 || action->text().compare( "Purple" ) == 0 || action->text().compare( "Orange" ) == 0 || action->text().compare( "Reset" ) == 0 ){

                    // Use helper method to find table row instead of O(n) loop
                    int row = findTableRowBySessionId(SessionID);
                    if (row != -1) {
                        QColor color = getSessionColor(action->text());
                        setRowColors(row, color, QColor(Util::ColorText::Colors::Hex::Foreground));
                    }
                    
                }
                else if ( action->text().compare( "Mark as Dead" ) == 0 || action->text().compare( "Mark as Alive" ) == 0 )
                {
                    // Use helper method instead of O(n) table search
                    int row = findTableRowBySessionId(SessionID);
                    if (row != -1) {
                        auto Package = new Util::Packager::Package;
                        Package->Head = Util::Packager::Head_t {
                            .Event= Util::Packager::Session::Type,
                            .User = HavocX::Teamserver.User.toStdString(),
                            .Time = CurrentTime().toStdString(),
                        };

                        QString marked;
                        if ( action->text().compare( "Mark as Alive" ) == 0 ) {
                            marked = "Alive";
                            Agent->Marked = marked;

                            auto icon = ( Agent->Elevated.compare( "true" ) == 0 ) ?
                                        WinVersionIcon( Agent->OS, true ) :
                                        WinVersionIcon( Agent->OS, false );

                            SessionTableWidget->SessionTableWidget->item( row, 0 )->setIcon( icon );
                            setRowColors(row, QColor(Util::ColorText::Colors::Hex::Background), QColor(Util::ColorText::Colors::Hex::Foreground));
                        }
                        else if ( action->text().compare( "Mark as Dead" ) == 0 ) {
                            marked = "Dead";
                            Agent->Marked = marked;

                            SessionTableWidget->SessionTableWidget->item( row, 0 )->setIcon( QIcon( ":/icons/DeadWhite" ) );
                            setRowColors(row, QColor(Util::ColorText::Colors::Hex::CurrentLine), QColor(Util::ColorText::Colors::Hex::Comment));
                        }

                        Package->Body = Util::Packager::Body_t {
                            .SubEvent = 0x5,
                            .Info = {
                                { "AgentID", SessionID.toStdString() },
                                { "Marked",  marked.toStdString() },
                            }
                        };

                        HavocX::Connector->SendPackage( Package );
                    }
                }
                else if ( action->text().compare( "Export" ) == 0 )
                {
                    Session.Export();
                }
                else if ( action->text().compare( "Remove" ) == 0 )
                {
                    auto SessionID = SessionTableWidget->SessionTableWidget->item( SessionTableWidget->SessionTableWidget->currentRow(), 0 )->text();
                    auto Agent = findSessionById(SessionID);
                    if (Agent) {
                        SessionTableWidget->SessionTableWidget->removeRow( SessionTableWidget->SessionTableWidget->currentRow() );
                        HavocX::Teamserver.TabSession->SessionGraphWidget->GraphNodeRemove( *Agent );
                    }
                }
                else if ( action->text().compare( "Mark Selected as Dead" ) == 0 || action->text().compare( "Mark Selected as Alive" ) == 0 )
                {
                    auto selectedRows = SessionTableWidget->SessionTableWidget->selectionModel()->selectedRows();
                    QString marked = action->text().compare( "Mark Selected as Alive" ) == 0 ? "Alive" : "Dead";

                    for ( const auto& index : selectedRows )
                    {
                        auto AgentID = SessionTableWidget->SessionTableWidget->item( index.row(), 0 )->text();
                        auto Agent = findSessionById(AgentID);
                        
                        if (Agent) {
                            auto Package = new Util::Packager::Package;
                            Package->Head = Util::Packager::Head_t {
                                .Event= Util::Packager::Session::Type,
                                .User = HavocX::Teamserver.User.toStdString(),
                                .Time = CurrentTime().toStdString(),
                            };

                            Agent->Marked = marked;

                            if ( marked.compare( "Alive" ) == 0 )
                            {
                                auto icon = ( Agent->Elevated.compare( "true" ) == 0 ) ?
                                            WinVersionIcon( Agent->OS, true ) :
                                            WinVersionIcon( Agent->OS, false );

                                SessionTableWidget->SessionTableWidget->item( index.row(), 0 )->setIcon( icon );
                                setRowColors(index.row(), QColor(Util::ColorText::Colors::Hex::Background), QColor(Util::ColorText::Colors::Hex::Foreground));
                            }
                            else
                            {
                                SessionTableWidget->SessionTableWidget->item( index.row(), 0 )->setIcon( QIcon( ":/icons/DeadWhite" ) );
                                setRowColors(index.row(), QColor(Util::ColorText::Colors::Hex::CurrentLine), QColor(Util::ColorText::Colors::Hex::Comment));
                            }

                            Package->Body = Util::Packager::Body_t {
                                .SubEvent = 0x5,
                                .Info = {
                                    { "AgentID", AgentID.toStdString() },
                                    { "Marked",  marked.toStdString() },
                                }
                            };

                            HavocX::Connector->SendPackage( Package );
                        }
                    }
                }
                else if ( action->text().compare( "Remove Selected" ) == 0 )
                {
                    auto selectedRows = SessionTableWidget->SessionTableWidget->selectionModel()->selectedRows();
                    
                    // Sort rows in descending order to remove from bottom up (avoid index shifting)
                    std::sort( selectedRows.begin(), selectedRows.end(), []( const QModelIndex& a, const QModelIndex& b ) {
                        return a.row() > b.row();
                    });

                    for ( const auto& index : selectedRows )
                    {
                        auto AgentID = SessionTableWidget->SessionTableWidget->item( index.row(), 0 )->text();
                        auto Agent = findSessionById(AgentID);
                        
                        if (Agent) {
                            SessionTableWidget->SessionTableWidget->removeRow( index.row() );
                            HavocX::Teamserver.TabSession->SessionGraphWidget->GraphNodeRemove( *Agent );
                        }
                    }
                }
                else if ( action->text().compare( "Remove All Dead Sessions" ) == 0 )
                {
                    // Collect all dead sessions first using O(n) instead of O(n²)
                    QList<int> deadRows;
                    for ( int i = 0; i < SessionTableWidget->SessionTableWidget->rowCount(); i++ )
                    {
                        auto AgentID = SessionTableWidget->SessionTableWidget->item( i, 0 )->text();
                        auto Agent = findSessionById(AgentID);
                        
                        if (Agent && Agent->Marked.compare( "Dead" ) == 0) {
                            deadRows.append( i );
                        }
                    }
                    
                    // Sort in descending order and remove from bottom up
                    std::sort( deadRows.begin(), deadRows.end(), std::greater<int>() );
                    
                    for ( int row : deadRows )
                    {
                        auto AgentID = SessionTableWidget->SessionTableWidget->item( row, 0 )->text();
                        auto Agent = findSessionById(AgentID);
                        
                        if (Agent) {
                            SessionTableWidget->SessionTableWidget->removeRow( row );
                            HavocX::Teamserver.TabSession->SessionGraphWidget->GraphNodeRemove( *Agent );
                        }
                    }
                }
                else if ( action->text().compare( "Thread" ) == 0 || action->text().compare( "Process" ) == 0 )
                {
                    Session.InteractedWidget->AppendText( "exit " + action->text().toLower() );
                }

                if ( IsValidDemonMagic(Session.MagicValue) )
                {
                    if ( action->text().compare( "Process List" ) == 0 )
                    {
                        auto TabName = QString( "[" + SessionID + "] Process List" );

                        if ( Session.ProcessList == nullptr )
                        {
                            Session.ProcessList = new UserInterface::Widgets::ProcessList;
                            Session.ProcessList->setupUi( new QWidget );
                            Session.ProcessList->Session = Session;
                            Session.ProcessList->Teamserver = HavocX::Teamserver.Name;

                            HavocX::Teamserver.TabSession->NewBottomTab( Session.ProcessList->ProcessListWidget, TabName.toStdString() );
                            Session.InteractedWidget->DemonCommands->Execute.ProcList( Util::gen_random( 8 ).c_str(), true );
                        }
                        else
                        {
                            HavocX::Teamserver.TabSession->NewBottomTab( Session.ProcessList->ProcessListWidget, TabName.toStdString() );
                        }
                    }
                    else if ( action->text().compare( "File Explorer" ) == 0 )
                    {
                        auto TabName = QString( "[" + SessionID + "] File Explorer" );

                        if ( Session.FileBrowser == nullptr )
                        {
                            Session.FileBrowser = new FileBrowser;
                            Session.FileBrowser->setupUi( new QWidget );
                            Session.FileBrowser->SessionID = Session.Name;

                            HavocX::Teamserver.TabSession->NewBottomTab( Session.FileBrowser->FileBrowserWidget, TabName.toStdString(), "" );
                            Session.InteractedWidget->DemonCommands->Execute.FS( Util::gen_random( 8 ).c_str(), "dir;ui", "." );
                        }
                        else
                        {
                            HavocX::Teamserver.TabSession->NewBottomTab( Session.FileBrowser->FileBrowserWidget, TabName.toStdString(), "" );
                        }
                    }
                }
            }
        }

    }

    delete separator;
    delete separator2;
    delete separator3;
    delete separator4;
}


void UserInterface::Widgets::TeamserverTabSession::NewBottomTab( QWidget* TabWidget, const string& TitleName, const QString IconPath ) const
{
    int id = 0;
    if ( tabWidget->count() == 0 )
    {
        splitter_TopBot->setSizes( QList<int>() << 100 << 200 );
        splitter_TopBot->setStyleSheet( "" );
    }
    else if ( tabWidget->count() == 1 )
        tabWidget->setMovable( true );

    tabWidget->setTabsClosable( true );

    id = tabWidget->addTab( TabWidget, TitleName.c_str() );

    tabWidget->setIconSize( QSize( 15, 15 ) );
    tabWidget->setCurrentIndex( id );
}

void UserInterface::Widgets::TeamserverTabSession::NewWidgetTab( QWidget *TabWidget, const std::string &TitleName ) const
{
    if ( tabWidgetSmall->count() == 0 ) {
        splitter_SessionAndTabs->setSizes( QList<int>() << 200 << 10 );
        splitter_SessionAndTabs->setStyleSheet( "" );
        splitter_SessionAndTabs->handle( 1 )->setEnabled( true );
        splitter_SessionAndTabs->handle( 1 )->setCursor( Qt::SplitHCursor );
    } else if ( tabWidgetSmall->count() == 1 ) {
        tabWidgetSmall->setMovable( true );
    }

    tabWidgetSmall->setTabsClosable( true );

    tabWidget->setCurrentIndex(
        tabWidgetSmall->addTab(
            TabWidget,
            TitleName.c_str()
        )
    );
}

void UserInterface::Widgets::TeamserverTabSession::removeTabSmall( int index ) const
{
    if ( index == -1 ) {
        return;
    }

    tabWidgetSmall->removeTab( index );

    if ( tabWidgetSmall->count() == 0 ) {
        splitter_SessionAndTabs->setSizes( QList<int>() << 0 );
        splitter_SessionAndTabs->setStyleSheet( "QSplitter::handle { image: url(images/notExists.png); }" );
        splitter_SessionAndTabs->handle( 1 )->setEnabled( false );
        splitter_SessionAndTabs->handle( 1 )->setCursor( Qt::ArrowCursor );
    } else if ( tabWidgetSmall->count() == 1 ) {
        tabWidgetSmall->setMovable( false );
    }
}

// Helper method to find session by ID - eliminates repeated loops
Util::SessionItem* UserInterface::Widgets::TeamserverTabSession::findSessionById(const QString& sessionId) {
    for (auto& session : HavocX::Teamserver.Sessions) {
        if (session.Name.compare(sessionId) == 0) {
            return &session;
        }
    }
    return nullptr;
}

// Helper method to find table row by session ID
int UserInterface::Widgets::TeamserverTabSession::findTableRowBySessionId(const QString& sessionId) {
    for (int i = 0; i < SessionTableWidget->SessionTableWidget->rowCount(); i++) {
        auto item = SessionTableWidget->SessionTableWidget->item(i, 0);
        if (item && item->text().compare(sessionId) == 0) {
            return i;
        }
    }
    return -1;
}

// Helper method to get color from name - eliminates massive if/else chains
QColor UserInterface::Widgets::TeamserverTabSession::getSessionColor(const QString& colorName) {
    if (colorName.compare("Red") == 0)
        return QColor(Util::ColorText::Colors::Hex::SessionRed);
    else if (colorName.compare("Blue") == 0)
        return QColor(Util::ColorText::Colors::Hex::SessionCyan);
    else if (colorName.compare("Pink") == 0)
        return QColor(Util::ColorText::Colors::Hex::SessionPink);
    else if (colorName.compare("Yellow") == 0)
        return QColor(Util::ColorText::Colors::Hex::SessionYellow);
    else if (colorName.compare("Green") == 0)
        return QColor(Util::ColorText::Colors::Hex::SessionGreen);
    else if (colorName.compare("Purple") == 0)
        return QColor(Util::ColorText::Colors::Hex::SessionPurple);
    else if (colorName.compare("Orange") == 0)
        return QColor(Util::ColorText::Colors::Hex::SessionOrange);
    else
        return QColor(Util::ColorText::Colors::Hex::Background);
}

// Helper method to set row colors - eliminates duplicate loops
void UserInterface::Widgets::TeamserverTabSession::setRowColors(int row, const QColor& bgColor, const QColor& fgColor) {
    if (row < 0 || row >= SessionTableWidget->SessionTableWidget->rowCount()) {
        return;
    }
    
    for (int j = 0; j < SessionTableWidget->SessionTableWidget->columnCount(); j++) {
        auto item = SessionTableWidget->SessionTableWidget->item(row, j);
        if (item) {
            item->setBackground(bgColor);
            item->setForeground(fgColor);
        }
    }
}
