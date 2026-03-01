#include <global.hpp>
#include <spdlog/spdlog.h>

#include <UserInterface/Widgets/ServerLootWidget.h>
#include <UserInterface/Widgets/LootWidget.h>  // For ImageLabel
#include <Havoc/Packager.hpp>
#include <Havoc/Connector.hpp>
#include <QGraphicsScene>
#include <QGraphicsView>
#include <QGraphicsPixmapItem>
#include <QLabel>
#include <QFile>
#include <QTreeWidgetItem>
#include <QHeaderView>
#include <QScrollBar>
#include <QKeyEvent>
#include <QGraphicsSceneWheelEvent>
#include <QTime>
#include <QFileDialog>
#include <QMessageBox>

ServerLootWidget::ServerLootWidget()
{
    if ( objectName().isEmpty() )
        setObjectName( QString::fromUtf8( "ServerLootWidget" ) );

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

    gridLayout = new QGridLayout( this );
    gridLayout->setContentsMargins( 0, 0, 0, 0 );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );
    
    LabelShow = new QLabel( this );
    LabelShow->setObjectName( QString::fromUtf8( "LabelShow" ) );

    gridLayout->addWidget( LabelShow, 0, 3, 1, 1 );

    ComboShow = new QComboBox( this );
    ComboShow->addItem( QString( "Screenshots" ) );
    ComboShow->addItem( QString( "Downloads" ) );
    ComboShow->setObjectName( QString::fromUtf8( "ComboShow" ) );
    ComboShow->setMinimumSize( QSize( 150, 0 ) );

    gridLayout->addWidget( ComboShow, 0, 4, 1, 1 );

    LabelAgentID = new QLabel( this );
    LabelAgentID->setObjectName( QString::fromUtf8( "LabelAgentID" ) );
    LabelAgentID->setText( "AgentID: " );
    gridLayout->addWidget( LabelAgentID, 0, 1, 1, 1 );

    ComboAgentID = new QComboBox( this );
    ComboAgentID->setObjectName( QString::fromUtf8( "ComboAgentID" ) );
    ComboAgentID->setMinimumSize( QSize( 150, 0 ) );
    gridLayout->addWidget( ComboAgentID, 0, 2, 1, 1 );

    // Add status label for server connection status
    LabelStatus = new QLabel( this );
    LabelStatus->setObjectName( QString::fromUtf8( "LabelStatus" ) );
    LabelStatus->setText( "Server: Connected" );
    LabelStatus->setStyleSheet( "color: #50fa7b;" ); // Dracula green
    gridLayout->addWidget( LabelStatus, 0, 5, 1, 1 );

    horizontalSpacer = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );
    gridLayout->addItem( horizontalSpacer, 0, 0, 1, 1 );

    StackWidget = new QStackedWidget( this );
    StackWidget->setObjectName( QString::fromUtf8( "StackWidget" ) );
    StackWidget->setContentsMargins( 0, 0, 0, 0 );

    Screenshots = new QWidget();
    Screenshots->setSizePolicy( QSizePolicy::Ignored, QSizePolicy::Ignored );

    Screenshots->setObjectName( QString::fromUtf8( "Screenshots" ) );
    gridLayout_2 = new QGridLayout( Screenshots );
    gridLayout_2->setObjectName( QString::fromUtf8( "gridLayout_2" ) );

    splitter = new QSplitter( Screenshots );
    splitter->setObjectName( QString::fromUtf8( "splitter" ) );
    splitter->setOrientation( Qt::Horizontal );
    splitter->setSizes( QList<int>() << 10 << 200 );

    ScreenshotTable = new QTableWidget( splitter );
    if ( ScreenshotTable->columnCount() < 6 )
        ScreenshotTable->setColumnCount( 6 );

    ScreenshotTable->setEnabled( true );
    ScreenshotTable->setShowGrid( false );
    ScreenshotTable->setSortingEnabled( false );
    ScreenshotTable->setWordWrap( true );
    ScreenshotTable->setCornerButtonEnabled( true );
    ScreenshotTable->horizontalHeader()->setVisible( true );
    ScreenshotTable->setSelectionBehavior( QAbstractItemView::SelectRows );
    ScreenshotTable->setContextMenuPolicy( Qt::CustomContextMenu );
    ScreenshotTable->horizontalHeader()->setSectionResizeMode( QHeaderView::Stretch );
    ScreenshotTable->verticalHeader()->setVisible(false);
    ScreenshotTable->verticalHeader()->setStretchLastSection( false );
    ScreenshotTable->verticalHeader()->setDefaultSectionSize( 12 );
    ScreenshotTable->setFocusPolicy( Qt::NoFocus );
    ScreenshotTable->setObjectName( QString::fromUtf8( "ScreenshotTable" ) );

    splitter->addWidget( ScreenshotTable );

    ScreenshotImage = new ImageLabel( splitter );
    ScreenshotImage->setObjectName( QString::fromUtf8( "ScreenshotImage" ) );

    splitter->addWidget( ScreenshotImage );

    gridLayout_2->addWidget(splitter, 0, 0, 1, 1);

    StackWidget->addWidget( Screenshots );
    Downloads = new QWidget();
    Downloads->setObjectName(QString::fromUtf8("Downloads"));
    gridLayout_3 = new QGridLayout( Downloads );
    gridLayout_3->setObjectName(QString::fromUtf8("gridLayout_3"));

    DownloadTable = new QTableWidget( Downloads );
    if ( DownloadTable->columnCount() < 7 )
        DownloadTable->setColumnCount( 7 );

    DownloadTable->setEnabled( true );
    DownloadTable->setShowGrid( false );
    DownloadTable->setSortingEnabled( false );
    DownloadTable->setWordWrap( true );
    DownloadTable->setCornerButtonEnabled( true );
    DownloadTable->horizontalHeader()->setVisible( true );
    DownloadTable->setSelectionBehavior( QAbstractItemView::SelectRows );
    DownloadTable->setContextMenuPolicy( Qt::CustomContextMenu );
    DownloadTable->horizontalHeader()->setSectionResizeMode( QHeaderView::Stretch );
    DownloadTable->verticalHeader()->setVisible(false);
    DownloadTable->verticalHeader()->setStretchLastSection( false );
    DownloadTable->verticalHeader()->setDefaultSectionSize( 12 );
    DownloadTable->setFocusPolicy( Qt::NoFocus );
    DownloadTable->setObjectName( QString::fromUtf8( "DownloadsTable" ) );

    gridLayout_3->addWidget( DownloadTable, 0, 0, 1, 1 );

    StackWidget->addWidget( Downloads );

    gridLayout->addWidget( StackWidget, 1, 0, 1, 7 );

    horizontalSpacer_2 = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );

    gridLayout->addItem( horizontalSpacer_2, 0, 6, 1, 1 );

    StackWidget->setCurrentIndex( 0 );

    ScreenshotTable->setHorizontalHeaderItem( 0, new QTableWidgetItem( "Name" ) );
    ScreenshotTable->setHorizontalHeaderItem( 1, new QTableWidgetItem( "Date" ) );
    ScreenshotTable->setHorizontalHeaderItem( 2, new QTableWidgetItem( "Operator" ) );
    ScreenshotTable->setHorizontalHeaderItem( 3, new QTableWidgetItem( "External IP" ) );
    ScreenshotTable->setHorizontalHeaderItem( 4, new QTableWidgetItem( "Hostname" ) );
    ScreenshotTable->setHorizontalHeaderItem( 5, new QTableWidgetItem( "Session ID" ) );

    DownloadTable->setHorizontalHeaderItem( 0, new QTableWidgetItem( "Name" ) );
    DownloadTable->setHorizontalHeaderItem( 1, new QTableWidgetItem( "Size" ) );
    DownloadTable->setHorizontalHeaderItem( 2, new QTableWidgetItem( "Date" ) );
    DownloadTable->setHorizontalHeaderItem( 3, new QTableWidgetItem( "Operator" ) );
    DownloadTable->setHorizontalHeaderItem( 4, new QTableWidgetItem( "External IP" ) );
    DownloadTable->setHorizontalHeaderItem( 5, new QTableWidgetItem( "Hostname" ) );
    DownloadTable->setHorizontalHeaderItem( 6, new QTableWidgetItem( "Session ID" ) );

    LabelShow->setText( "Show: " );

    // Server-focused context menus (no "Download from Server" option since we ARE the server view)
    ScreenshotMenu           = new QMenu( this );
    ScreenshotActionDownload = new QAction( "Download" );
    ScreenshotActionDelete   = new QAction( "Delete from Server" );
    ScreenshotActionRefresh  = new QAction( "Refresh" );

    DownloadMenu           = new QMenu( this );
    DownloadActionDownload = new QAction( "Download" );
    DownloadActionDelete   = new QAction( "Delete from Server" );
    DownloadActionRefresh  = new QAction( "Refresh" );

    ScreenshotMenu->setStyleSheet( MenuStyle );
    ScreenshotMenu->addAction( ScreenshotActionDownload );
    ScreenshotMenu->addSeparator();
    ScreenshotMenu->addAction( ScreenshotActionDelete );
    ScreenshotMenu->addSeparator();
    ScreenshotMenu->addAction( ScreenshotActionRefresh );

    DownloadMenu->setStyleSheet( MenuStyle );
    DownloadMenu->addAction( DownloadActionDownload );
    DownloadMenu->addSeparator();
    DownloadMenu->addAction( DownloadActionDelete );
    DownloadMenu->addSeparator();
    DownloadMenu->addAction( DownloadActionRefresh );

    connect( ScreenshotTable, &QTableWidget::clicked, this, &ServerLootWidget::onScreenshotTableClick );
    connect( DownloadTable, &QTableWidget::clicked, this, &ServerLootWidget::onDownloadTableClick );
    connect( splitter, &QSplitter::splitterMoved, ScreenshotImage, &ImageLabel::resizeImage );
    connect( ComboAgentID, &QComboBox::currentTextChanged, this, &ServerLootWidget::onAgentChange );
    connect( ComboShow, &QComboBox::currentTextChanged, this, &ServerLootWidget::onShowChange );
    connect( ScreenshotTable, &QTableWidget::customContextMenuRequested, this, &ServerLootWidget::onScreenshotTableCtx );
    connect( DownloadTable, &QTableWidget::customContextMenuRequested, this, &ServerLootWidget::onDownloadTableCtx );
    connect( ScreenshotActionDownload, &QAction::triggered, this, &ServerLootWidget::onScreenshotDownload );
    connect( DownloadActionDownload, &QAction::triggered, this, &ServerLootWidget::onDownloadDownload );
    connect( ScreenshotActionDelete, &QAction::triggered, this, &ServerLootWidget::onScreenshotDelete );
    connect( DownloadActionDelete, &QAction::triggered, this, &ServerLootWidget::onDownloadDelete );
    connect( ScreenshotActionRefresh, &QAction::triggered, this, &ServerLootWidget::onRefresh );
    connect( DownloadActionRefresh, &QAction::triggered, this, &ServerLootWidget::onRefresh );

    Reload();
    
    // Request loot sync from server to load persistent data
    RequestLootSync();

    QMetaObject::connectSlotsByName( this );
}

void ServerLootWidget::AddServerSideScreenshot( const QString& DemonID, const QString& Name, const QString& Date, const QString& RelativePath, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID )
{

    auto Item = ServerLootData{
        .Type = LOOT_IMAGE,
        .AgentID = DemonID,
        .RelativePath = RelativePath,
        .Operator = Operator,
        .ExternalIP = ExternalIP,
        .Hostname = Hostname,
        .SessionID = SessionID,
        .FileSize = 0, // Will be updated when downloaded
        .Timestamp = Date,
        .Downloaded = false,
        .CachedData = QByteArray(),
        .Display = {
            .Name = Name,
            .Date = Date,
        },
    };

    ServerLootItems.push_back( Item );
    
    // Add to agent list if not already present
    AddSessionSection( DemonID );
    
    // Update table if current agent filter matches
    if ( ComboAgentID->currentText().compare( DemonID ) == 0 || ComboAgentID->currentText().compare( "[ All ]" ) == 0 )
    {
        ScreenshotTableAdd( Name, Date, Operator, ExternalIP, Hostname, SessionID );
    }
}

void ServerLootWidget::AddServerSideDownload( const QString& DemonID, const QString& Name, const QString& Size, const QString& Date, const QString& RelativePath, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID )
{

    auto Item = ServerLootData{
        .Type = LOOT_FILE,
        .AgentID = DemonID,
        .RelativePath = RelativePath,
        .Operator = Operator,
        .ExternalIP = ExternalIP,
        .Hostname = Hostname,
        .SessionID = SessionID,
        .FileSize = Size.toLongLong(),
        .Timestamp = Date,
        .Downloaded = false,
        .CachedData = QByteArray(),
        .Display = {
            .Name = Name,
            .Date = Date,
            .Size = Size,
        },
    };

    ServerLootItems.push_back( Item );
    
    // Add to agent list if not already present
    AddSessionSection( DemonID );
    
    // Update table if current agent filter matches
    if ( ComboAgentID->currentText().compare( DemonID ) == 0 || ComboAgentID->currentText().compare( "[ All ]" ) == 0 )
    {
        DownloadTableAdd( Name, Size, Date, Operator, ExternalIP, Hostname, SessionID );
    }
}

void ServerLootWidget::AddSessionSection( const QString& AgentID )
{
    for ( int index = 0; index < ComboAgentID->count(); index++ )
    {
        if ( ComboAgentID->itemText( index ).compare( AgentID ) == 0 )
        {
            return;
        }
    }

    ComboAgentID->addItem( AgentID );
}

void ServerLootWidget::onScreenshotTableClick( const QModelIndex &index )
{
    auto DemonID  = ComboAgentID->currentText();
    auto FileName = ScreenshotTable->item( index.row(), 0 )->text();

    for ( auto& item : ServerLootItems )
    {
        if ( DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( item.AgentID ) == 0 )
        {
            if ( item.Type == LOOT_IMAGE )
            {
                if ( item.Display.Name.compare( FileName ) == 0 )
                {
                    if ( !item.Downloaded || item.CachedData.isEmpty() )
                    {
                        // Request file from server
                        RequestServerLootFile( item.AgentID, item.RelativePath );
                        LabelStatus->setText( "Status: Downloading..." );
                        LabelStatus->setStyleSheet( "color: #ffb86c;" ); // Dracula orange
                    }
                    else
                    {
                        // Display cached data immediately
                        auto image = QPixmap();
                        if ( image.loadFromData( item.CachedData ) )
                        {
                            ScreenshotImage->setPixmap( image );
                            LabelStatus->setText( "Status: Ready" );
                            LabelStatus->setStyleSheet( "color: #50fa7b;" ); // Dracula green
                        }
                    }
                    break;
                }
            }
        }
    }
}

void ServerLootWidget::onDownloadTableClick( const QModelIndex &index )
{
    // For downloads, we don't auto-download on click, just show info
    LabelStatus->setText( "Status: Right-click to download" );
    LabelStatus->setStyleSheet( "color: #6272a4;" ); // Dracula comment
}

void ServerLootWidget::onAgentChange( const QString& text )
{
    ScreenshotImage->setPixmap( QPixmap() );

    // Clear tables
    for ( int i = ScreenshotTable->rowCount(); i >= 0; i-- )
        ScreenshotTable->removeRow( i );
    for ( int i = DownloadTable->rowCount(); i >= 0; i-- )
        DownloadTable->removeRow( i );

    for ( auto& item : ServerLootItems )
    {
        if ( item.AgentID.compare( text ) == 0 || text.compare( "[ All ]" ) == 0 )
        {
            switch ( item.Type )
            {
                case LOOT_IMAGE:
                {
                    ScreenshotTableAdd( item.Display.Name, item.Display.Date, item.Operator, item.ExternalIP, item.Hostname, item.SessionID );
                    break;
                }

                case LOOT_FILE:
                {
                    DownloadTableAdd( item.Display.Name, item.Display.Size, item.Display.Date, item.Operator, item.ExternalIP, item.Hostname, item.SessionID );
                    break;
                }
            }
        }
    }
    
    LabelStatus->setText( "Status: Filtered by " + text );
    LabelStatus->setStyleSheet( "color: #bd93f9;" ); // Dracula purple
}

void ServerLootWidget::onShowChange( const QString& text )
{
    if ( text.compare( "Screenshots" ) == 0 )
    {
        StackWidget->setCurrentIndex( 0 );
    }
    else if ( text.compare( "Downloads" ) == 0 )
    {
        StackWidget->setCurrentIndex( 1 );
    }
}

void ServerLootWidget::ScreenshotTableAdd( const QString& Name, const QString& Date, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID )
{
    ScreenshotTable->setRowCount( ScreenshotTable->rowCount() + 1 );

    QTableWidgetItem* nameItem = new QTableWidgetItem(Name);
    nameItem->setTextAlignment(Qt::AlignCenter);
    ScreenshotTable->setItem(ScreenshotTable->rowCount() - 1, 0, nameItem);

    QTableWidgetItem* dateItem = new QTableWidgetItem(Date);
    dateItem->setTextAlignment(Qt::AlignCenter);
    ScreenshotTable->setItem(ScreenshotTable->rowCount() - 1, 1, dateItem);

    QTableWidgetItem* operatorItem = new QTableWidgetItem(Operator);
    operatorItem->setTextAlignment(Qt::AlignCenter);
    ScreenshotTable->setItem(ScreenshotTable->rowCount() - 1, 2, operatorItem);

    QTableWidgetItem* ipItem = new QTableWidgetItem(ExternalIP);
    ipItem->setTextAlignment(Qt::AlignCenter);
    ScreenshotTable->setItem(ScreenshotTable->rowCount() - 1, 3, ipItem);

    QTableWidgetItem* hostnameItem = new QTableWidgetItem(Hostname);
    hostnameItem->setTextAlignment(Qt::AlignCenter);
    ScreenshotTable->setItem(ScreenshotTable->rowCount() - 1, 4, hostnameItem);

    QTableWidgetItem* sessionItem = new QTableWidgetItem(SessionID);
    sessionItem->setTextAlignment(Qt::AlignCenter);
    ScreenshotTable->setItem(ScreenshotTable->rowCount() - 1, 5, sessionItem);
}

void ServerLootWidget::DownloadTableAdd( const QString& Name, const QString& Size, const QString& Date, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID )
{
    DownloadTable->setRowCount( DownloadTable->rowCount() + 1 );

    QTableWidgetItem* nameItem = new QTableWidgetItem(Name);
    nameItem->setTextAlignment(Qt::AlignCenter);
    DownloadTable->setItem(DownloadTable->rowCount() - 1, 0, nameItem);

    QTableWidgetItem* sizeItem = new QTableWidgetItem(Size);
    sizeItem->setTextAlignment(Qt::AlignCenter);
    DownloadTable->setItem(DownloadTable->rowCount() - 1, 1, sizeItem);

    QTableWidgetItem* dateItem = new QTableWidgetItem(Date);
    dateItem->setTextAlignment(Qt::AlignCenter);
    DownloadTable->setItem(DownloadTable->rowCount() - 1, 2, dateItem);

    QTableWidgetItem* operatorItem = new QTableWidgetItem(Operator);
    operatorItem->setTextAlignment(Qt::AlignCenter);
    DownloadTable->setItem(DownloadTable->rowCount() - 1, 3, operatorItem);

    QTableWidgetItem* ipItem = new QTableWidgetItem(ExternalIP);
    ipItem->setTextAlignment(Qt::AlignCenter);
    DownloadTable->setItem(DownloadTable->rowCount() - 1, 4, ipItem);

    QTableWidgetItem* hostnameItem = new QTableWidgetItem(Hostname);
    hostnameItem->setTextAlignment(Qt::AlignCenter);
    DownloadTable->setItem(DownloadTable->rowCount() - 1, 5, hostnameItem);

    QTableWidgetItem* sessionItem = new QTableWidgetItem(SessionID);
    sessionItem->setTextAlignment(Qt::AlignCenter);
    DownloadTable->setItem(DownloadTable->rowCount() - 1, 6, sessionItem);
}

void ServerLootWidget::onScreenshotTableCtx( const QPoint &pos )
{
    if ( ! ScreenshotTable->itemAt( pos ) )
        return;

    ScreenshotMenu->popup( ScreenshotTable->viewport()->mapToGlobal( pos ) );
}

void ServerLootWidget::onDownloadTableCtx( const QPoint &pos )
{
    if ( ! DownloadTable->itemAt( pos ) )
        return;

    DownloadMenu->popup( DownloadTable->viewport()->mapToGlobal( pos ) );
}

void ServerLootWidget::onScreenshotDownload()
{
    auto selectedItems = ScreenshotTable->selectedItems();
    if ( selectedItems.isEmpty() ) return;

    auto row = selectedItems[0]->row();
    auto fileName = ScreenshotTable->item( row, 0 )->text();
    auto DemonID = ComboAgentID->currentText();

    // Find server-side screenshot item
    for ( auto& item : ServerLootItems )
    {
        if ( (DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( item.AgentID ) == 0) &&
             item.Type == LOOT_IMAGE && item.Display.Name.compare( fileName ) == 0 )
        {
            if ( item.CachedData.isEmpty() )
            {
                // Request file from server - UpdateServerLootFileResponse will handle save dialog
                RequestServerLootFile( item.AgentID, item.RelativePath );
                LabelStatus->setText( "Status: Downloading from server..." );
                LabelStatus->setStyleSheet( "color: #ffb86c;" ); // Dracula orange
            }
            else
            {
                // File already cached, show save dialog immediately
                auto savePath = QFileDialog::getSaveFileName( this, "Save Server Screenshot", fileName, "PNG Files (*.png);;All Files (*)" );
                if ( !savePath.isEmpty() )
                {
                    QFile file( savePath );
                    if ( file.open( QIODevice::WriteOnly ) )
                    {
                        file.write( item.CachedData );
                        file.close();
                        LabelStatus->setText( "Status: Downloaded to " + savePath );
                        LabelStatus->setStyleSheet( "color: #50fa7b;" ); // Dracula green
                    }
                    else
                    {
                        QMessageBox::critical( this, "Error", "Failed to save file: " + file.errorString() );
                        LabelStatus->setText( "Status: Download failed" );
                        LabelStatus->setStyleSheet( "color: #ff5555;" ); // Dracula red
                    }
                }
            }
            break;
        }
    }
}

void ServerLootWidget::onDownloadDownload()
{
    auto selectedItems = DownloadTable->selectedItems();
    if ( selectedItems.isEmpty() ) return;

    auto row = selectedItems[0]->row();
    auto fileName = DownloadTable->item( row, 0 )->text();
    auto DemonID = ComboAgentID->currentText();

    // Find server-side download item
    for ( auto& item : ServerLootItems )
    {
        if ( (DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( item.AgentID ) == 0) &&
             item.Type == LOOT_FILE && item.Display.Name.compare( fileName ) == 0 )
        {
            if ( item.CachedData.isEmpty() )
            {
                // Request file from server - UpdateServerLootFileResponse will handle save dialog
                RequestServerLootFile( item.AgentID, item.RelativePath );
                LabelStatus->setText( "Status: Downloading from server..." );
                LabelStatus->setStyleSheet( "color: #ffb86c;" ); // Dracula orange
            }
            else
            {
                // File already cached, show save dialog immediately
                auto savePath = QFileDialog::getSaveFileName( this, "Save Server Download", fileName, "All Files (*)" );
                if ( !savePath.isEmpty() )
                {
                    QFile file( savePath );
                    if ( file.open( QIODevice::WriteOnly ) )
                    {
                        file.write( item.CachedData );
                        file.close();
                        LabelStatus->setText( "Status: Downloaded to " + savePath );
                        LabelStatus->setStyleSheet( "color: #50fa7b;" ); // Dracula green
                    }
                    else
                    {
                        QMessageBox::critical( this, "Error", "Failed to save file: " + file.errorString() );
                        LabelStatus->setText( "Status: Download failed" );
                        LabelStatus->setStyleSheet( "color: #ff5555;" ); // Dracula red
                    }
                }
            }
            break;
        }
    }
}

void ServerLootWidget::onScreenshotDelete()
{
    auto selectedItems = ScreenshotTable->selectedItems();
    if ( selectedItems.isEmpty() ) return;

    auto row = selectedItems[0]->row();
    auto fileName = ScreenshotTable->item( row, 0 )->text();
    auto DemonID = ComboAgentID->currentText();

    // Confirm deletion
    auto reply = QMessageBox::question( this, "Confirm Deletion", 
        "Are you sure you want to delete '" + fileName + "' from the server?\nThis action cannot be undone.", 
        QMessageBox::Yes | QMessageBox::No );
    
    if ( reply == QMessageBox::Yes )
    {
        // Find and remove the item
        for ( auto it = ServerLootItems.begin(); it != ServerLootItems.end(); ++it )
        {
            if ( (DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( it->AgentID ) == 0) &&
                 it->Type == LOOT_IMAGE && it->Display.Name.compare( fileName ) == 0 )
            {
                // Request deletion from server
                RequestDeleteLootFile( it->AgentID, it->RelativePath );
                
                // Remove from local cache
                ServerLootItems.erase( it );
                
                // Remove from table
                ScreenshotTable->removeRow( row );
                
                LabelStatus->setText( "Status: Deleted " + fileName );
                LabelStatus->setStyleSheet( "color: #ff5555;" ); // Dracula red
                break;
            }
        }
    }
}

void ServerLootWidget::onDownloadDelete()
{
    auto selectedItems = DownloadTable->selectedItems();
    if ( selectedItems.isEmpty() ) return;

    auto row = selectedItems[0]->row();
    auto fileName = DownloadTable->item( row, 0 )->text();
    auto DemonID = ComboAgentID->currentText();

    // Confirm deletion
    auto reply = QMessageBox::question( this, "Confirm Deletion", 
        "Are you sure you want to delete '" + fileName + "' from the server?\nThis action cannot be undone.", 
        QMessageBox::Yes | QMessageBox::No );
    
    if ( reply == QMessageBox::Yes )
    {
        // Find and remove the item
        for ( auto it = ServerLootItems.begin(); it != ServerLootItems.end(); ++it )
        {
            if ( (DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( it->AgentID ) == 0) &&
                 it->Type == LOOT_FILE && it->Display.Name.compare( fileName ) == 0 )
            {
                // Request deletion from server
                RequestDeleteLootFile( it->AgentID, it->RelativePath );
                
                // Remove from local cache
                ServerLootItems.erase( it );
                
                // Remove from table
                DownloadTable->removeRow( row );
                
                LabelStatus->setText( "Status: Deleted " + fileName );
                LabelStatus->setStyleSheet( "color: #ff5555;" ); // Dracula red
                break;
            }
        }
    }
}

void ServerLootWidget::onRefresh()
{
    LabelStatus->setText( "Status: Refreshing..." );
    LabelStatus->setStyleSheet( "color: #ffb86c;" ); // Dracula orange
    
    // Clear current data and request fresh sync
    ClearLoot();
    RequestLootSync();
}

void ServerLootWidget::RequestServerLootFile( const QString& AgentID, const QString& RelativePath )
{
    // Create packet to request loot file from server
    auto Package = Util::Packager::Package{
        .Head = {
            .Event   = Util::Packager::Loot::Type,
            .User    = HavocX::Teamserver.User.toStdString(),
            .Time    = QTime::currentTime().toString( "hh:mm:ss" ).toStdString(),
            .OneTime = "false",
        },
        .Body = {
            .SubEvent = Util::Packager::Loot::GetFile,
            .Info = {
                { "AgentID", AgentID.toStdString() },
                { "RelativePath", RelativePath.toStdString() },
            },
        },
    };

    HavocX::Connector->SendPackage( &Package );
}

void ServerLootWidget::RequestLootSync()
{
    // Create packet to request all loot from server
    auto Package = Util::Packager::Package{
        .Head = {
            .Event   = Util::Packager::Loot::Type,
            .User    = HavocX::Teamserver.User.toStdString(),
            .Time    = QTime::currentTime().toString( "hh:mm:ss" ).toStdString(),
            .OneTime = "false",
        },
        .Body = {
            .SubEvent = Util::Packager::Loot::SyncAll,
            .Info = {},
        },
    };

    HavocX::Connector->SendPackage( &Package );
}

void ServerLootWidget::RequestDeleteLootFile( const QString& AgentID, const QString& RelativePath )
{
    // Create packet to delete loot file from server
    auto Package = Util::Packager::Package{
        .Head = {
            .Event   = Util::Packager::Loot::Type,
            .User    = HavocX::Teamserver.User.toStdString(),
            .Time    = QTime::currentTime().toString( "hh:mm:ss" ).toStdString(),
            .OneTime = "false",
        },
        .Body = {
            .SubEvent = Util::Packager::Loot::Delete,
            .Info = {
                { "AgentID", AgentID.toStdString() },
                { "RelativePath", RelativePath.toStdString() },
            },
        },
    };

    HavocX::Connector->SendPackage( &Package );
}

void ServerLootWidget::Reload()
{
    ComboAgentID->clear();
    ComboAgentID->addItem( "[ All ]" );

    for ( auto& Session : HavocX::Teamserver.Sessions )
        ComboAgentID->addItem( Session.Name );

    // Clear tables
    ScreenshotTable->setRowCount( 0 );
    DownloadTable->setRowCount( 0 );
    
    LabelStatus->setText( "Status: Ready" );
    LabelStatus->setStyleSheet( "color: #50fa7b;" ); // Dracula green
}

void ServerLootWidget::ClearLoot()
{
    // Clear all server loot items
    ServerLootItems.clear();
    
    // Clear tables
    ScreenshotTable->setRowCount( 0 );
    DownloadTable->setRowCount( 0 );
    
    // Clear image view
    ScreenshotImage->setPixmap( QPixmap() );
    
    LabelStatus->setText( "Status: Cleared" );
    LabelStatus->setStyleSheet( "color: #6272a4;" ); // Dracula comment
}

void ServerLootWidget::UpdateServerLootFileResponse( const QString& AgentID, const QString& RelativePath, const QByteArray& FileData )
{
    // Find the corresponding server loot item and update its cached data
    for ( auto& item : ServerLootItems )
    {
        if ( item.AgentID == AgentID && item.RelativePath == RelativePath )
        {
            item.CachedData = FileData;
            item.Downloaded = true;
            
            // If this is an image, display it and update status
            if ( item.Type == LOOT_IMAGE )
            {
                auto image = QPixmap();
                if ( image.loadFromData( FileData ) )
                {
                    ScreenshotImage->setPixmap( image );
                    LabelStatus->setText( "Status: Image loaded - Right-click to download" );
                    LabelStatus->setStyleSheet( "color: #50fa7b;" ); // Dracula green
                }
                else
                {
                    spdlog::error( "Failed to load image data from server" );
                    LabelStatus->setText( "Status: Image load failed" );
                    LabelStatus->setStyleSheet( "color: #ff5555;" ); // Dracula red
                }
            }
            else if ( item.Type == LOOT_FILE )
            {
                // For downloads, automatically show save dialog
                auto savePath = QFileDialog::getSaveFileName( this, "Save Server Download", item.Display.Name, "All Files (*)" );
                if ( !savePath.isEmpty() )
                {
                    QFile file( savePath );
                    if ( file.open( QIODevice::WriteOnly ) )
                    {
                        file.write( FileData );
                        file.close();
                        LabelStatus->setText( "Status: Downloaded to " + savePath );
                        LabelStatus->setStyleSheet( "color: #50fa7b;" ); // Dracula green
                    }
                    else
                    {
                        QMessageBox::critical( this, "Error", "Failed to save file: " + file.errorString() );
                        LabelStatus->setText( "Status: Download failed" );
                        LabelStatus->setStyleSheet( "color: #ff5555;" ); // Dracula red
                    }
                }
                else
                {
                    LabelStatus->setText( "Status: Download cancelled" );
                    LabelStatus->setStyleSheet( "color: #6272a4;" ); // Dracula comment
                }
            }
            break;
        }
    }
}
