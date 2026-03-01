#include <global.hpp>
#include <spdlog/spdlog.h>

#include <UserInterface/Widgets/LootWidget.h>
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

// imagelabel.cpp
ImageLabel::ImageLabel( QWidget* parent ) : QWidget( parent )
{
    label      = new QLabel;
    scrollArea = new QScrollArea( this );

    label->setBackgroundRole( QPalette::Base );
    label->setSizePolicy( QSizePolicy::Ignored, QSizePolicy::Ignored );
    label->setScaledContents( true );
    label->setStyleSheet( "background-color: #282a36;\n"
                          "    color: #f8f8f2;" );
    label->setPixmap( QPixmap() );

    scrollArea->setBackgroundRole(QPalette::Dark);
    scrollArea->setWidget( label );
}

void ImageLabel::resizeEvent( QResizeEvent* event )
{
    QWidget::resizeEvent( event );
    resizeImage();
}

const QPixmap* ImageLabel::pixmap() const
{
    return label->pixmap();
}

bool ImageLabel::event( QEvent* e )
{
    if ( e->type() == e->KeyPress )
    {
        auto eventKey = dynamic_cast<QKeyEvent*>( e );

        if ( eventKey->key() == Qt::Key_Control )
        {
            // spdlog::info( "Key_Control pressed" );
            key_ctrl = false;
        }
    }

    return QWidget::event( e );
}

void ImageLabel::keyReleaseEvent( QKeyEvent* event )
{
    if ( event->key() == Qt::Key_Control )
    {
        // spdlog::info( "Key_Control released" );
        key_ctrl = true;
    }

    QWidget::keyReleaseEvent( event );
}

void ImageLabel::wheelEvent( QWheelEvent* ev )
{
    // spdlog::info( "wheelEvent: {}", ev->angleDelta().y() );

    QWidget::wheelEvent( ev );
}

void ImageLabel::setPixmap( const QPixmap &pixmap )
{
    label->setPixmap( pixmap );
    scrollArea->setWidget( label );
    resizeImage();
}

void ImageLabel::resizeImage()
{
    label->setMinimumSize( size() );
    label->adjustSize();
    scrollArea->resize( size() );
}

LootWidget::LootWidget()
{
    if ( objectName().isEmpty() )
        setObjectName( QString::fromUtf8( "LootWidget" ) );

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

    gridLayout->addWidget( StackWidget, 1, 0, 1, 6 );

    horizontalSpacer_2 = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );

    gridLayout->addItem( horizontalSpacer_2, 0, 5, 1, 1 );

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

    // Operator-focused context menus (local session-only)
    ScreenshotMenu           = new QMenu( this );
    ScreenshotActionDownload = new QAction( "Download" );
    ScreenshotActionDelete = new QAction( "Delete" );

    DownloadMenu           = new QMenu( this );
    DownloadActionDownload = new QAction( "Download" );
    DownloadActionDelete = new QAction( "Delete" );

    ScreenshotMenu->setStyleSheet( MenuStyle );
    ScreenshotMenu->addAction( ScreenshotActionDownload );
    ScreenshotMenu->addSeparator();
    ScreenshotMenu->addAction( ScreenshotActionDelete );

    DownloadMenu->setStyleSheet( MenuStyle );
    DownloadMenu->addAction( DownloadActionDownload );
    DownloadMenu->addSeparator();
    DownloadMenu->addAction( DownloadActionDelete );

    connect( ScreenshotTable, &QTableWidget::clicked, this, &LootWidget::onScreenshotTableClick );
    connect( DownloadTable, &QTableWidget::clicked, this, &LootWidget::onDownloadTableClick );
    connect( splitter, &QSplitter::splitterMoved, ScreenshotImage, &ImageLabel::resizeImage );
    connect( ComboAgentID, &QComboBox::currentTextChanged, this, &LootWidget::onAgentChange );
    connect( ComboShow, &QComboBox::currentTextChanged, this, &LootWidget::onShowChange );
    connect( ScreenshotTable, &QTableWidget::customContextMenuRequested, this, &LootWidget::onScreenshotTableCtx );
    connect( DownloadTable, &QTableWidget::customContextMenuRequested, this, &LootWidget::onDownloadTableCtx );
    connect( ScreenshotActionDownload, &QAction::triggered, this, &LootWidget::onScreenshotDownload );
    connect( DownloadActionDownload, &QAction::triggered, this, &LootWidget::onDownloadDownload );
    connect( ScreenshotActionDelete, &QAction::triggered, this, &LootWidget::onScreenshotDelete );
    connect( DownloadActionDelete, &QAction::triggered, this, &LootWidget::onDownloadDelete );

    Reload();
    
    // Note: Operator loot is session-only, no server sync needed

    QMetaObject::connectSlotsByName( this );
}

void LootWidget::AddScreenshot( const QString& DemonID, const QString& Name, const QString& Date, const QByteArray& Data )
{
    spdlog::info( "Add Screenshot" );

    auto Item = LootData{
        .Type       = LOOT_IMAGE,
        .AgentID    = DemonID,
        .IsServerSide = false,
        .Data       = {
            .Name   = Name,
            .Date   = Date,
            .Data   = Data,
        },
    };

    LootItems.push_back( Item );

    if ( ComboAgentID->currentText().compare( DemonID ) == 0 || ComboAgentID->currentText().compare( "[ All ]" ) == 0 )
    {
        ScreenshotTable->setRowCount( ScreenshotTable->rowCount() + 1 );

        QTableWidgetItem* nameItem = new QTableWidgetItem(Name);
        nameItem->setTextAlignment(Qt::AlignCenter);
        ScreenshotTable->setItem(ScreenshotTable->rowCount() - 1, 0, nameItem);

        QTableWidgetItem* dateItem = new QTableWidgetItem(Date);
        dateItem->setTextAlignment(Qt::AlignCenter);
        ScreenshotTable->setItem(ScreenshotTable->rowCount() - 1, 1, dateItem);
    }
}

void LootWidget::AddScreenshotWithMetadata( const QString& DemonID, const QString& Name, const QString& Date, const QByteArray& Data, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID )
{
    spdlog::info( "Add Screenshot with enhanced metadata" );

    auto Item = LootData{
        .Type       = LOOT_IMAGE,
        .AgentID    = DemonID,
        .IsServerSide = false,
        .Data       = {
            .Name   = Name,
            .Date   = Date,
            .Data   = Data,
        },
    };

    LootItems.push_back( Item );

    if ( ComboAgentID->currentText().compare( DemonID ) == 0 || ComboAgentID->currentText().compare( "[ All ]" ) == 0 )
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
}

void LootWidget::AddDownload( const QString &DemonID, const QString &Name, const QString& Size, const QString &Date, const QByteArray &Data )
{
    auto Item = LootData{
        .Type       = LOOT_FILE,
        .AgentID    = DemonID,
        .IsServerSide = false,
        .Data       = {
            .Name = Name,
            .Date = Date,
            .Size = Size,
            .Data = Data,
        },
    };

    LootItems.push_back( Item );

    if ( ComboAgentID->currentText().compare( DemonID ) == 0 || ComboAgentID->currentText().compare( "[ All ]" ) == 0 )
    {
        DownloadTable->setRowCount( DownloadTable->rowCount() + 1 );

        QTableWidgetItem* downloadNameItem = new QTableWidgetItem(Name);
        downloadNameItem->setTextAlignment(Qt::AlignCenter);
        DownloadTable->setItem(DownloadTable->rowCount() - 1, 0, downloadNameItem);

        QTableWidgetItem* downloadSizeItem = new QTableWidgetItem(Size);
        downloadSizeItem->setTextAlignment(Qt::AlignCenter);
        DownloadTable->setItem(DownloadTable->rowCount() - 1, 1, downloadSizeItem);

        QTableWidgetItem* downloadDateItem = new QTableWidgetItem(Date);
        downloadDateItem->setTextAlignment(Qt::AlignCenter);
        DownloadTable->setItem(DownloadTable->rowCount() - 1, 2, downloadDateItem);
    }
}

void LootWidget::AddDownloadWithMetadata( const QString& DemonID, const QString& Name, const QString& Size, const QString& Date, const QByteArray& Data, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID )
{
    spdlog::info( "Add Download with enhanced metadata" );

    auto Item = LootData{
        .Type       = LOOT_FILE,
        .AgentID    = DemonID,
        .IsServerSide = false,
        .Data       = {
            .Name = Name,
            .Date = Date,
            .Size = Size,
            .Data = Data,
        },
    };

    LootItems.push_back( Item );

    if ( ComboAgentID->currentText().compare( DemonID ) == 0 || ComboAgentID->currentText().compare( "[ All ]" ) == 0 )
    {
        DownloadTable->setRowCount( DownloadTable->rowCount() + 1 );

        QTableWidgetItem* downloadNameItem = new QTableWidgetItem(Name);
        downloadNameItem->setTextAlignment(Qt::AlignCenter);
        DownloadTable->setItem(DownloadTable->rowCount() - 1, 0, downloadNameItem);

        QTableWidgetItem* downloadSizeItem = new QTableWidgetItem(Size);
        downloadSizeItem->setTextAlignment(Qt::AlignCenter);
        DownloadTable->setItem(DownloadTable->rowCount() - 1, 1, downloadSizeItem);

        QTableWidgetItem* downloadDateItem = new QTableWidgetItem(Date);
        downloadDateItem->setTextAlignment(Qt::AlignCenter);
        DownloadTable->setItem(DownloadTable->rowCount() - 1, 2, downloadDateItem);

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
}

void LootWidget::Reload()
{
    ComboAgentID->clear();
    ComboAgentID->addItem( "[ All ]" );

    for ( auto& Session : HavocX::Teamserver.Sessions )
        ComboAgentID->addItem( Session.Name );

    // TODO: iterate over table items and free memory
    ScreenshotTable->setRowCount( 0 );
    DownloadTable->setRowCount( 0 );
}

void LootWidget::ClearLoot()
{
    // Clear all loot items
    LootItems.clear();
    
    // Clear tables
    ScreenshotTable->setRowCount( 0 );
    DownloadTable->setRowCount( 0 );
    
    // Clear image view
    ScreenshotImage->setPixmap( QPixmap() );
}

void LootWidget::onScreenshotTableClick( const QModelIndex &index )
{
    auto DemonID  = ComboAgentID->currentText();
    auto FileName = ScreenshotTable->item( index.row(), 0 )->text();

    for ( auto& item : LootItems )
    {
        if ( DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( item.AgentID ) == 0 )
        {
            if ( item.Type == LOOT_IMAGE )
            {
                if ( item.Data.Name.compare( FileName ) == 0 )
                {
                    // Only handle local (operator) loot - no server-side requests
                    if ( !item.IsServerSide )
                    {
                        // Display local loot immediately
                        auto image = QPixmap();
                        if ( image.loadFromData( item.Data.Data, "BMP" ) )
                        {
                            ScreenshotImage->setPixmap( image );
                        }
                    }
                    break;
                }
            }
        }
    }
}

void LootWidget::onDownloadTableClick( const QModelIndex &index )
{

}

void LootWidget::onAgentChange( const QString& text )
{
    ScreenshotImage->setPixmap( QPixmap() );

    // todo: free columns items
    for ( int i = ScreenshotTable->rowCount(); i >= 0; i-- )
        ScreenshotTable->removeRow( i );

    for ( auto& item : LootItems )
    {
        if ( item.AgentID.compare( text ) == 0 || text.compare( "[ All ]" ) == 0 )
        {
            switch ( item.Type )
            {
                case LOOT_IMAGE:
                {
                    ScreenshotTableAdd( item.Data.Name, item.Data.Date );
                    break;
                }

                case LOOT_FILE:
                {
                    DownloadTableAdd( item.Data.Name, item.Data.Size, item.Data.Date );
                    break;
                }
            }
        }
    }
}

void LootWidget::AddSessionSection( const QString& AgentID )
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

void LootWidget::onShowChange( const QString& text )
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

void LootWidget::ScreenshotTableAdd( const QString& Name, const QString& Date )
{
    ScreenshotTable->setRowCount( ScreenshotTable->rowCount() + 1 );

    auto NameItem = new QTableWidgetItem( Name );
    auto DateItem = new QTableWidgetItem( Date );

    // Set text alignment to center for all items (fixes UI alignment bug)
    NameItem->setTextAlignment(Qt::AlignCenter);
    DateItem->setTextAlignment(Qt::AlignCenter);

    NameItem->setFlags( NameItem->flags() &~ Qt::ItemIsEditable );
    DateItem->setFlags( DateItem->flags() &~ Qt::ItemIsEditable );

    ScreenshotTable->setItem( ScreenshotTable->rowCount() - 1, 0, NameItem );
    ScreenshotTable->setItem( ScreenshotTable->rowCount() - 1, 1, DateItem );
}

void LootWidget::ScreenshotTableAdd( const QString& Name, const QString& Date, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID )
{
    ScreenshotTable->setRowCount( ScreenshotTable->rowCount() + 1 );

    auto NameItem = new QTableWidgetItem( Name );
    auto DateItem = new QTableWidgetItem( Date );
    auto OperatorItem = new QTableWidgetItem( Operator );
    auto ExternalIPItem = new QTableWidgetItem( ExternalIP );
    auto HostnameItem = new QTableWidgetItem( Hostname );
    auto SessionIDItem = new QTableWidgetItem( SessionID );

    // Set text alignment to center for all items (fixes UI alignment bug)
    NameItem->setTextAlignment(Qt::AlignCenter);
    DateItem->setTextAlignment(Qt::AlignCenter);
    OperatorItem->setTextAlignment(Qt::AlignCenter);
    ExternalIPItem->setTextAlignment(Qt::AlignCenter);
    HostnameItem->setTextAlignment(Qt::AlignCenter);
    SessionIDItem->setTextAlignment(Qt::AlignCenter);

    NameItem->setFlags( NameItem->flags() &~ Qt::ItemIsEditable );
    DateItem->setFlags( DateItem->flags() &~ Qt::ItemIsEditable );
    OperatorItem->setFlags( OperatorItem->flags() &~ Qt::ItemIsEditable );
    ExternalIPItem->setFlags( ExternalIPItem->flags() &~ Qt::ItemIsEditable );
    HostnameItem->setFlags( HostnameItem->flags() &~ Qt::ItemIsEditable );
    SessionIDItem->setFlags( SessionIDItem->flags() &~ Qt::ItemIsEditable );

    int row = ScreenshotTable->rowCount() - 1;
    ScreenshotTable->setItem( row, 0, NameItem );
    ScreenshotTable->setItem( row, 1, DateItem );
    ScreenshotTable->setItem( row, 2, OperatorItem );
    ScreenshotTable->setItem( row, 3, ExternalIPItem );
    ScreenshotTable->setItem( row, 4, HostnameItem );
    ScreenshotTable->setItem( row, 5, SessionIDItem );
}

void LootWidget::DownloadTableAdd( const QString &Name, const QString &Size, const QString &Date )
{
    auto item_Name = new QTableWidgetItem( Name );
    auto item_Size = new QTableWidgetItem( Size );
    auto item_Date = new QTableWidgetItem( Date );

    item_Name->setTextAlignment( Qt::AlignCenter );
    item_Name->setFlags( item_Name->flags() ^ Qt::ItemIsEditable );

    item_Size->setTextAlignment( Qt::AlignCenter );
    item_Size->setFlags( item_Size->flags() ^ Qt::ItemIsEditable );

    item_Date->setTextAlignment( Qt::AlignCenter );
    item_Date->setFlags( item_Date->flags() ^ Qt::ItemIsEditable );

    DownloadTable->rowCount() < 1 ? DownloadTable->setRowCount( 1 ) : DownloadTable->setRowCount( DownloadTable->rowCount() + 1 );

    DownloadTable->setItem( DownloadTable->rowCount() - 1, 0, item_Name );
    DownloadTable->setItem( DownloadTable->rowCount() - 1, 1, item_Size );
    DownloadTable->setItem( DownloadTable->rowCount() - 1, 2, item_Date );
}

void LootWidget::DownloadTableAdd( const QString& Name, const QString& Size, const QString& Date, const QString& Operator, const QString& ExternalIP, const QString& Hostname, const QString& SessionID )
{
    DownloadTable->setRowCount( DownloadTable->rowCount() + 1 );

    auto NameItem = new QTableWidgetItem( Name );
    auto SizeItem = new QTableWidgetItem( Size );
    auto DateItem = new QTableWidgetItem( Date );
    auto OperatorItem = new QTableWidgetItem( Operator );
    auto ExternalIPItem = new QTableWidgetItem( ExternalIP );
    auto HostnameItem = new QTableWidgetItem( Hostname );
    auto SessionIDItem = new QTableWidgetItem( SessionID );

    // Set text alignment to center for all items (fixes UI alignment bug)
    NameItem->setTextAlignment(Qt::AlignCenter);
    SizeItem->setTextAlignment(Qt::AlignCenter);
    DateItem->setTextAlignment(Qt::AlignCenter);
    OperatorItem->setTextAlignment(Qt::AlignCenter);
    ExternalIPItem->setTextAlignment(Qt::AlignCenter);
    HostnameItem->setTextAlignment(Qt::AlignCenter);
    SessionIDItem->setTextAlignment(Qt::AlignCenter);

    NameItem->setFlags( NameItem->flags() &~ Qt::ItemIsEditable );
    SizeItem->setFlags( SizeItem->flags() &~ Qt::ItemIsEditable );
    DateItem->setFlags( DateItem->flags() &~ Qt::ItemIsEditable );
    OperatorItem->setFlags( OperatorItem->flags() &~ Qt::ItemIsEditable );
    ExternalIPItem->setFlags( ExternalIPItem->flags() &~ Qt::ItemIsEditable );
    HostnameItem->setFlags( HostnameItem->flags() &~ Qt::ItemIsEditable );
    SessionIDItem->setFlags( SessionIDItem->flags() &~ Qt::ItemIsEditable );

    int row = DownloadTable->rowCount() - 1;
    DownloadTable->setItem( row, 0, NameItem );
    DownloadTable->setItem( row, 1, SizeItem );
    DownloadTable->setItem( row, 2, DateItem );
    DownloadTable->setItem( row, 3, OperatorItem );
    DownloadTable->setItem( row, 4, ExternalIPItem );
    DownloadTable->setItem( row, 5, HostnameItem );
    DownloadTable->setItem( row, 6, SessionIDItem );
}

void LootWidget::onScreenshotTableCtx( const QPoint &pos )
{
    if ( ! ScreenshotTable->itemAt( pos ) )
        return;

    ScreenshotMenu->popup( ScreenshotTable->viewport()->mapToGlobal( pos ) );
}

void LootWidget::onDownloadTableCtx( const QPoint &pos )
{
    if ( ! DownloadTable->itemAt( pos ) )
        return;

    DownloadMenu->popup( DownloadTable->viewport()->mapToGlobal( pos ) );
}

void LootWidget::onScreenshotDownload()
{
    // Download local screenshot
    auto selectedItems = ScreenshotTable->selectedItems();
    if ( selectedItems.isEmpty() ) return;

    auto row = selectedItems[0]->row();
    auto fileName = ScreenshotTable->item( row, 0 )->text();
    auto DemonID = ComboAgentID->currentText();

    // Find local screenshot item
    for ( auto& item : LootItems )
    {
        if ( (DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( item.AgentID ) == 0) &&
             item.Type == LOOT_IMAGE && item.Data.Name.compare( fileName ) == 0 && !item.IsServerSide )
        {
            auto savePath = QFileDialog::getSaveFileName( this, "Save Screenshot", fileName, "PNG Files (*.png);;BMP Files (*.bmp);;All Files (*)" );
            if ( !savePath.isEmpty() )
            {
                QFile file( savePath );
                if ( file.open( QIODevice::WriteOnly ) )
                {
                    file.write( item.Data.Data );
                    file.close();
                    QMessageBox::information( this, "Success", "Screenshot saved successfully!" );
                }
                else
                {
                    QMessageBox::critical( this, "Error", "Failed to save screenshot!" );
                }
            }
            break;
        }
    }
}

void LootWidget::onDownloadDownload()
{
    // Download local file
    auto selectedItems = DownloadTable->selectedItems();
    if ( selectedItems.isEmpty() ) return;

    auto row = selectedItems[0]->row();
    auto fileName = DownloadTable->item( row, 0 )->text();
    auto DemonID = ComboAgentID->currentText();

    // Find local download item
    for ( auto& item : LootItems )
    {
        if ( (DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( item.AgentID ) == 0) &&
             item.Type == LOOT_FILE && item.Data.Name.compare( fileName ) == 0 && !item.IsServerSide )
        {
            auto savePath = QFileDialog::getSaveFileName( this, "Save File", fileName, "All Files (*)" );
            if ( !savePath.isEmpty() )
            {
                QFile file( savePath );
                if ( file.open( QIODevice::WriteOnly ) )
                {
                    file.write( item.Data.Data );
                    file.close();
                    QMessageBox::information( this, "Success", "File saved successfully!" );
                }
                else
                {
                    QMessageBox::critical( this, "Error", "Failed to save file!" );
                }
            }
            break;
        }
    }
}

void LootWidget::onScreenshotDelete()
{
    // Delete local screenshot only
    auto selectedItems = ScreenshotTable->selectedItems();
    if ( selectedItems.isEmpty() ) return;

    auto row = selectedItems[0]->row();
    auto fileName = ScreenshotTable->item( row, 0 )->text();
    auto DemonID = ComboAgentID->currentText();

    // Show confirmation dialog
    auto reply = QMessageBox::question( this, "Delete Screenshot", 
        QString("Are you sure you want to delete the screenshot '%1'?\n\nNote: This only removes it from this session.").arg(fileName),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No );

    if ( reply != QMessageBox::Yes ) return;

    // Find and remove local screenshot item
    for ( auto it = LootItems.begin(); it != LootItems.end(); ++it )
    {
        if ( (DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( it->AgentID ) == 0) &&
             it->Type == LOOT_IMAGE && it->Data.Name.compare( fileName ) == 0 && !it->IsServerSide )
        {
            // Remove local item
            LootItems.erase( it );
            
            // Remove from table
            ScreenshotTable->removeRow( row );
            
            // Clear image view if this was the displayed image
            ScreenshotImage->setPixmap( QPixmap() );
            
            QMessageBox::information( this, "Success", "Screenshot removed from this session!" );
            break;
        }
    }
}

void LootWidget::onDownloadDelete()
{
    // Delete local download only
    auto selectedItems = DownloadTable->selectedItems();
    if ( selectedItems.isEmpty() ) return;

    auto row = selectedItems[0]->row();
    auto fileName = DownloadTable->item( row, 0 )->text();
    auto DemonID = ComboAgentID->currentText();

    // Show confirmation dialog
    auto reply = QMessageBox::question( this, "Delete File", 
        QString("Are you sure you want to delete the file '%1'?\n\nNote: This only removes it from this session.").arg(fileName),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No );

    if ( reply != QMessageBox::Yes ) return;

    // Find and remove local download item
    for ( auto it = LootItems.begin(); it != LootItems.end(); ++it )
    {
        if ( (DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( it->AgentID ) == 0) &&
             it->Type == LOOT_FILE && it->Data.Name.compare( fileName ) == 0 && !it->IsServerSide )
        {
            // Remove local item
            LootItems.erase( it );
            
            // Remove from table
            DownloadTable->removeRow( row );
            
            QMessageBox::information( this, "Success", "File removed from this session!" );
            break;
        }
    }
}
