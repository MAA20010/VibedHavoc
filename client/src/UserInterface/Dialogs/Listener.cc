#include <global.hpp>

#include <UserInterface/Dialogs/Listener.hpp>

#include <QFile>
#include <QApplication>
#include <QDialog>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpacerItem>
#include <QFileDialog>
#include <QMessageBox>
#include <QIODevice>
#include <QRandomGenerator>
#include <sstream>

using namespace HavocNamespace::HavocSpace;
using namespace HavocNamespace::UserInterface::Dialogs;

// Generate a random 32-character hex PSK
static QString generateRandomPSK() {
    QString psk;
    const char hexChars[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        psk += hexChars[QRandomGenerator::global()->bounded(16)];
    }
    return psk;
}

bool is_number( const std::string& s )
{
    std::string::const_iterator it = s.begin();
    while (it != s.end() && std::isdigit(*it)) ++it;
    return !s.empty() && it == s.end();
}

NewListener::NewListener( QDialog* Dialog )
{
    ListenerDialog = Dialog;

    if ( ListenerDialog->objectName().isEmpty() )
        ListenerDialog->setObjectName( QString::fromUtf8( "ListenerWidget" ) );

    Dialog->setStyleSheet( FileRead( ":/stylesheets/Dialogs/Listener" ) );

    ListenerDialog->resize( 750, 850 );

    gridLayout = new QGridLayout( ListenerDialog );
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    
    // Set column stretch factors so Name/Payload fields expand with window
    gridLayout->setColumnStretch(0, 0);  // Label column - fixed width
    gridLayout->setColumnStretch(1, 1);  // Fields start - expandable
    gridLayout->setColumnStretch(2, 1);  // Fields continue - expandable
    gridLayout->setColumnStretch(3, 1);  // Fields continue - expandable
    gridLayout->setColumnStretch(4, 1);  // Fields continue - expandable
    gridLayout->setColumnStretch(5, 1);  // Fields end - expandable

    ConfigBox = new QGroupBox( ListenerDialog );
    ConfigBox->setObjectName(QString::fromUtf8("ConfigBox"));

    gridLayout_2 = new QGridLayout( ConfigBox );
    gridLayout_2->setObjectName( QString::fromUtf8( "gridLayout_2" ) );
    gridLayout_2->setHorizontalSpacing( 0 );
    gridLayout_2->setContentsMargins( 0, 0, 0, 0 );

    StackWidgetConfigPages = new QStackedWidget( ConfigBox );
    StackWidgetConfigPages->setObjectName( QString::fromUtf8( "StackWidgetConfigPages" ) );

    // ============
    // === HTTP ===
    // ============
    PageHTTP = new QWidget();
    PageHTTP->setObjectName( QString::fromUtf8( "PageHTTP" ) );

    LabelHosts              = new QLabel( PageHTTP );
    HostsGroup              = new QGroupBox( PageHTTP );
    ButtonHostsGroupAdd     = new QPushButton( PageHTTP );
    ButtonHostsGroupClear   = new QPushButton( PageHTTP );

    LabelHostRotation       = new QLabel( PageHTTP );
    ComboHostRotation       = new QComboBox( PageHTTP );

    LabelHostBind           = new QLabel( PageHTTP );
    ComboHostBind           = new QComboBox( PageHTTP );

    LabelPortBind           = new QLabel( PageHTTP );
    InputPortBind           = new QLineEdit( PageHTTP );

    LabelPortConn           = new QLabel( PageHTTP );
    InputPortConn           = new QLineEdit( PageHTTP );

    LabelPSKHttp            = new QLabel( PageHTTP );
    InputPSKHttp            = new QLineEdit( PageHTTP );
    InputPSKHttp->setEchoMode( QLineEdit::PasswordEchoOnEdit );

    LabelUserAgent          = new QLabel( PageHTTP );
    InputUserAgent          = new QLineEdit( PageHTTP );

    LabelHeaders            = new QLabel( PageHTTP );
    HeadersGroup            = new QGroupBox( PageHTTP );
    ButtonHeaderGroupAdd    = new QPushButton( PageHTTP );
    ButtonHeaderGroupClear  = new QPushButton( PageHTTP );

    LabelUris               = new QLabel( PageHTTP );
    UrisGroup               = new QGroupBox( PageHTTP );
    ButtonUriGroupClear     = new QPushButton( PageHTTP );
    ButtonUriGroupAdd       = new QPushButton( PageHTTP );

    LabelHostHeader         = new QLabel( PageHTTP );
    InputHostHeader         = new QLineEdit( PageHTTP );

    CheckEnableProxy        = new QCheckBox( PageHTTP );

    horizontalSpacer_6      = new QSpacerItem( 0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum );
    verticalSpacer          = new QSpacerItem( 20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding );
    verticalSpacerHeader    = new QSpacerItem( 20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding );
    ProxyConfigBox          = new QGroupBox( PageHTTP );
    verticalSpacerUris      = new QSpacerItem( 20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding );

    formLayout_Hosts        = new QFormLayout( HostsGroup );
    formLayout_Header       = new QFormLayout( HeadersGroup );
    formLayout_Uri          = new QFormLayout( UrisGroup );
    formLayout_3            = new QFormLayout( ProxyConfigBox );

    LabelProxyType = new QLabel( ProxyConfigBox );
    ComboProxyType = new QComboBox( ProxyConfigBox );
    LabelProxyHost = new QLabel( ProxyConfigBox );
    InputProxyHost = new QLineEdit( ProxyConfigBox );
    LabelProxyPort = new QLabel( ProxyConfigBox );
    InputProxyPort = new QLineEdit( ProxyConfigBox );
    LabelUserName  = new QLabel( ProxyConfigBox );
    InputUserName  = new QLineEdit( ProxyConfigBox );
    LabelPassword  = new QLabel( ProxyConfigBox );
    InputPassword  = new QLineEdit( ProxyConfigBox );

    formLayout_3->setWidget( 0, QFormLayout::LabelRole, LabelProxyType );
    formLayout_3->setWidget( 0, QFormLayout::FieldRole, ComboProxyType );
    formLayout_3->setWidget( 1, QFormLayout::LabelRole, LabelProxyHost );
    formLayout_3->setWidget( 1, QFormLayout::FieldRole, InputProxyHost );
    formLayout_3->setWidget( 2, QFormLayout::LabelRole, LabelProxyPort );
    formLayout_3->setWidget( 2, QFormLayout::FieldRole, InputProxyPort );
    formLayout_3->setWidget( 3, QFormLayout::LabelRole, LabelUserName );
    formLayout_3->setWidget( 3, QFormLayout::FieldRole, InputUserName );
    formLayout_3->setWidget( 4, QFormLayout::LabelRole, LabelPassword );
    formLayout_3->setWidget( 4, QFormLayout::FieldRole, InputPassword );

    // Populate HostBind from server IPs (with safe fallbacks if not yet received)
    {
        auto ServerIPs = HavocX::Teamserver.IpAddresses;
        ComboHostBind->addItems( QStringList() << ServerIPs << "127.0.0.1" << "0.0.0.0" );
    }

    CheckEnableProxy->setObjectName( "bool" );
    ProxyConfigBox->setEnabled( true );
    InputUserAgent->setText( "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" ); // default. maybe make it dynamic/random ?
    InputUserAgent->setCursorPosition( 0 );
    InputPortBind->setText( "443" );
    InputPortConn->setText( "443" );

    // =============
    // ==== SMB ====
    // =============
    PageSMB = new QWidget();
    PageSMB->setObjectName(QString::fromUtf8("PageSMB"));
    formLayout = new QFormLayout( PageSMB );
    formLayout->setObjectName(QString::fromUtf8("formLayout"));
    LabelPipeName = new QLabel( PageSMB );
    LabelPipeName->setObjectName(QString::fromUtf8("LabelPipeName"));

    formLayout->setWidget(0, QFormLayout::LabelRole, LabelPipeName);

    InputPipeName = new QLineEdit( PageSMB );
    InputPipeName->setObjectName( QString::fromUtf8( "InputPipeName" ) );

    formLayout->setWidget(0, QFormLayout::FieldRole, InputPipeName);

    LabelPSKSmb = new QLabel( PageSMB );
    LabelPSKSmb->setObjectName(QString::fromUtf8("LabelPSKSmb"));
    InputPSKSmb = new QLineEdit( PageSMB );
    InputPSKSmb->setObjectName( QString::fromUtf8( "InputPSKSmb" ) );
    InputPSKSmb->setEchoMode( QLineEdit::PasswordEchoOnEdit );
    formLayout->setWidget(1, QFormLayout::LabelRole, LabelPSKSmb);
    formLayout->setWidget(1, QFormLayout::FieldRole, InputPSKSmb);

    // ==============
    // == External ==
    // ==============
    PageExternal = new QWidget();
    PageExternal->setObjectName(QString::fromUtf8("PageExternal"));
    formLayout_2 = new QFormLayout(PageExternal);
    formLayout_2->setObjectName(QString::fromUtf8("formLayout_2"));
    LabelEndpoint = new QLabel(PageExternal);
    LabelEndpoint->setObjectName(QString::fromUtf8("LabelEndpoint"));

    formLayout_2->setWidget(0, QFormLayout::LabelRole, LabelEndpoint);

    InputEndpoint = new QLineEdit(PageExternal);
    InputEndpoint->setObjectName(QString::fromUtf8("InputEndpoint"));

    formLayout_2->setWidget(0, QFormLayout::FieldRole, InputEndpoint);

    gridLayout_2->addWidget( StackWidgetConfigPages, 0, 0, 1, 1 );


    gridLayout->addWidget(ConfigBox, 3, 0, 1, 6);

    ComboPayload = new QComboBox( ListenerDialog );
    ComboPayload->setObjectName( QString::fromUtf8( "ComboPayload" ) );

    gridLayout->addWidget(ComboPayload, 1, 1, 1, 5);

    LabelListenerName = new QLabel(ListenerDialog);
    LabelListenerName->setObjectName(QString::fromUtf8("LabelListenerName"));

    gridLayout->addWidget(LabelListenerName, 0, 0, 1, 1);

    LabelPayload = new QLabel(ListenerDialog);
    LabelPayload->setObjectName(QString::fromUtf8("LabelPayload"));

    gridLayout->addWidget(LabelPayload, 1, 0, 1, 1);

    InputListenerName = new QLineEdit(ListenerDialog);
    InputListenerName->setObjectName(QString::fromUtf8("InputListenerName"));

    gridLayout->addWidget(InputListenerName, 0, 1, 1, 5);

    // Create horizontal layout for centered buttons
    QWidget* buttonWidget = new QWidget(ListenerDialog);
    QHBoxLayout* buttonLayout = new QHBoxLayout(buttonWidget);
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    
    buttonLayout->addStretch(1);
    
    ButtonLoadConfig = new QPushButton(ListenerDialog);
    ButtonLoadConfig->setObjectName(QString::fromUtf8("ButtonLoadConfig"));
    buttonLayout->addWidget(ButtonLoadConfig);
    
    ButtonSave = new QPushButton(ListenerDialog);
    ButtonSave->setObjectName(QString::fromUtf8("ButtonSave"));
    buttonLayout->addWidget(ButtonSave);
    
    ButtonClose = new QPushButton(ListenerDialog);
    ButtonClose->setObjectName(QString::fromUtf8("ButtonClose"));
    buttonLayout->addWidget(ButtonClose);
    
    buttonLayout->addStretch(1);
    
    // Add button container to grid spanning all columns
    gridLayout->addWidget(buttonWidget, 4, 0, 1, 6);

    horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer, 2, 0, 1, 6);

    StackWidgetConfigPages->setCurrentIndex( 0 );

    // Page HTTP/HTTPs
    gridLayout_3 = new QGridLayout( PageHTTP );
    gridLayout_3->setObjectName( QString::fromUtf8( "gridLayout_3" ) );

    gridLayout_3->addWidget( LabelUserAgent, 9, 0, 1, 1 );
    gridLayout_3->addWidget( ButtonUriGroupClear, 16, 2, 1, 1 );
    gridLayout_3->addWidget( ComboHostBind, 5, 1, 1, 2 );
    gridLayout_3->addWidget( LabelUris, 15, 0, 1, 1 );
    gridLayout_3->addWidget( LabelHostHeader, 19, 0, 1, 1 );
    gridLayout_3->addWidget( InputPortBind, 6, 1, 1, 2 );
    gridLayout_3->addWidget( InputPortConn, 7, 1, 1, 2 );
    gridLayout_3->addWidget( LabelPSKHttp, 8, 0, 1, 1 );
    gridLayout_3->addWidget( InputPSKHttp, 8, 1, 1, 2 );
    gridLayout_3->addWidget( CheckEnableProxy, 20, 0, 1, 3 );
    gridLayout_3->addWidget( ButtonHeaderGroupClear, 11, 2, 1, 1 );
    gridLayout_3->addWidget( InputHostHeader, 19, 1, 1, 2 );
    gridLayout_3->addWidget( LabelHeaders, 10, 0, 1, 1 );
    gridLayout_3->addWidget( ButtonHostsGroupAdd, 0, 2, 1, 1 );
    gridLayout_3->addWidget( LabelHostBind, 5, 0, 1, 1 );
    gridLayout_3->addWidget( InputUserAgent, 9, 1, 1, 2 );
    gridLayout_3->addWidget( ButtonUriGroupAdd, 15, 2, 1, 1 );
    gridLayout_3->addWidget( HeadersGroup, 10, 1, 3, 1 );
    gridLayout_3->addWidget( LabelHosts, 0, 0, 1, 1 );
    gridLayout_3->addWidget( ButtonHostsGroupClear, 1, 2, 1, 1 );
    gridLayout_3->addWidget( ButtonHeaderGroupAdd, 10, 2, 1, 1 );
    gridLayout_3->addWidget( HostsGroup, 0, 1, 4, 1 );
    gridLayout_3->addWidget( LabelPortBind, 6, 0, 1, 1 );
    gridLayout_3->addWidget( LabelPortConn, 7, 0, 1, 1 );
    gridLayout_3->addWidget( ProxyConfigBox, 21, 0, 1, 3 );
    gridLayout_3->addWidget( UrisGroup, 15, 1, 3, 1 );
    gridLayout_3->addWidget( LabelHostRotation, 4, 0, 1, 1 );
    gridLayout_3->addWidget( ComboHostRotation, 4, 1, 1, 2 );
    gridLayout_3->addItem( horizontalSpacer_6, 18, 1, 1, 1 );
    gridLayout_3->addItem( verticalSpacer, 2, 0, 1, 1 );
    gridLayout_3->addItem( verticalSpacerHeader, 12, 0, 1, 1 );
    gridLayout_3->addItem( verticalSpacerUris, 17, 0, 1, 1 );

    ProxyConfigBox->setEnabled( false );

    InputProxyHost->setReadOnly( true );
    InputProxyPort->setReadOnly( true );
    InputUserName->setReadOnly( true );
    InputPassword->setReadOnly( true );

    InputProxyHost->setPlaceholderText( "" );

    LabelProxyHost->setEnabled( false );
    LabelProxyPort->setEnabled( false );
    LabelUserName->setEnabled( false );
    LabelPassword->setEnabled( false );

    auto style = QString( "color: #44475a;" );
    LabelProxyType->setStyleSheet( style );
    LabelProxyHost->setStyleSheet( style );
    LabelProxyPort->setStyleSheet( style );
    LabelUserName->setStyleSheet( style );
    LabelPassword->setStyleSheet( style );

    // Add Pages
    StackWidgetConfigPages->addWidget( PageHTTP );
    StackWidgetConfigPages->addWidget( PageSMB );
    StackWidgetConfigPages->addWidget( PageExternal );

    ListenerDialog->setWindowTitle( "Create Listener" );
    LabelPayload->setText(QCoreApplication::translate("ListenerWidget", "Payload: ", nullptr));
    ComboPayload->setItemText(0, QCoreApplication::translate("ListenerWidget", "Https", nullptr));
    ComboPayload->setItemText(1, QCoreApplication::translate("ListenerWidget", "Http", nullptr));
    ComboPayload->setItemText(2, QCoreApplication::translate("ListenerWidget", "Smb", nullptr));
    ComboPayload->setItemText(3, QCoreApplication::translate("ListenerWidget", "External", nullptr));

    LabelListenerName->setText(QCoreApplication::translate("ListenerWidget", "Name:", nullptr));
    ButtonSave->setText(QCoreApplication::translate("ListenerWidget", "Save", nullptr));
    ButtonClose->setText(QCoreApplication::translate("ListenerWidget", "Close", nullptr));
    ButtonLoadConfig->setText(QCoreApplication::translate("ListenerWidget", "Load Config", nullptr));
    ConfigBox->setTitle(QCoreApplication::translate("ListenerWidget", "Config Options", nullptr));
    LabelUserAgent->setText(QCoreApplication::translate("ListenerWidget", "User Agent:  ", nullptr));
    ButtonUriGroupClear->setText(QCoreApplication::translate("ListenerWidget", "Clear", nullptr));
    LabelUris->setText(QCoreApplication::translate("ListenerWidget", "Uris:", nullptr));
    LabelHostHeader->setText(QCoreApplication::translate("ListenerWidget", "Host Header: ", nullptr));
    CheckEnableProxy->setText(QCoreApplication::translate("ListenerWidget", "Enable Proxy connection", nullptr));
    ButtonHeaderGroupClear->setText(QCoreApplication::translate("ListenerWidget", "Clear", nullptr));
    LabelHeaders->setText(QCoreApplication::translate("ListenerWidget", "Headers:", nullptr));
    ButtonHostsGroupAdd->setText(QCoreApplication::translate("ListenerWidget", "Add", nullptr));
    LabelHostBind->setText(QCoreApplication::translate("ListenerWidget", "Host (Bind):", nullptr));
    ButtonUriGroupAdd->setText(QCoreApplication::translate("ListenerWidget", "Add", nullptr));
    LabelHosts->setText(QCoreApplication::translate("ListenerWidget", "Hosts", nullptr));
    ButtonHostsGroupClear->setText(QCoreApplication::translate("ListenerWidget", "Clear", nullptr));
    ButtonHeaderGroupAdd->setText(QCoreApplication::translate("ListenerWidget", "Add", nullptr));
    LabelPortBind->setText(QCoreApplication::translate("ListenerWidget", "PortBind:", nullptr));
    LabelPortConn->setText(QCoreApplication::translate("ListenerWidget", "PortConn:", nullptr));
    LabelPSKHttp->setText(QCoreApplication::translate("ListenerWidget", "PSK:", nullptr));
    LabelProxyType->setText(QCoreApplication::translate("ListenerWidget", "Proxy Type:", nullptr));
    LabelProxyHost->setText(QCoreApplication::translate("ListenerWidget", "Proxy Host:", nullptr));
    LabelProxyPort->setText(QCoreApplication::translate("ListenerWidget", "Proxy Port: ", nullptr));
    LabelUserName->setText(QCoreApplication::translate("ListenerWidget", "UserName: ", nullptr));
    LabelPassword->setText(QCoreApplication::translate("ListenerWidget", "Password: ", nullptr));
    LabelHostRotation->setText(QCoreApplication::translate("ListenerWidget", "Host Rotation: ", nullptr));
    LabelPipeName->setText(QCoreApplication::translate("ListenerWidget", "Pipe Name: ", nullptr));
    LabelPSKSmb->setText(QCoreApplication::translate("ListenerWidget", "PSK:", nullptr));
    LabelEndpoint->setText(QCoreApplication::translate("ListenerWidget", "Endpoint: ", nullptr));

    ComboPayload->addItem( "Https" );
    ComboPayload->addItem( "Http" );
    ComboPayload->addItem( "Smb" );
    ComboPayload->addItem( "External" );

    ComboProxyType->addItem( "http" );
    ComboProxyType->addItem( "https" );

    ComboHostRotation->addItem( "round-robin" );
    ComboHostRotation->addItem( "random" );

    QObject::connect( ButtonSave, &QPushButton::clicked, this, &NewListener::onButton_Save );
    QObject::connect( ButtonLoadConfig, &QPushButton::clicked, this, &NewListener::onButton_LoadConfig );
    QObject::connect( ButtonClose, &QPushButton::clicked, this, [&]()
    {
        this->DialogClosed = true;
        this->ListenerDialog->close();

        // Free();
    } );

    QObject::connect( ButtonHostsGroupAdd, &QPushButton::clicked, this, [&]()
    {
        // Snapshot the current server IP list. If the server hasn't sent
        // its interface list yet, warn the user instead of showing an empty combo.
        auto ServerIPs = HavocX::Teamserver.IpAddresses;

        if ( ServerIPs.isEmpty() )
        {
            QMessageBox::warning(
                ListenerDialog,
                "Not Ready",
                "Server network interfaces have not been received yet.\n"
                "Please wait a moment and try again."
            );
            return;
        }

        auto Item = new QComboBox;
        Item->setEditable( true );
        Item->addItems( ServerIPs );
        Item->setFocus();

        if ( HostsData.size() == 0 && Item->count() > 0 ) {
            Item->setCurrentIndex( 0 );
        }

        formLayout_Hosts->setWidget( HostsData.size(), QFormLayout::FieldRole, Item );

        HostsData.push_back( Item );
    } );

    QObject::connect( ButtonHostsGroupClear, &QPushButton::clicked, this, [&]()
    {
        for ( auto& uri : HostsData )
            delete uri;

        HostsData.clear();
    } );

    QObject::connect( ButtonUriGroupAdd, &QPushButton::clicked, this, [&]()
    {
        auto Item = new QLineEdit;
        Item->setFocus();

        formLayout_Uri->setWidget( UrisData.size(), QFormLayout::FieldRole, Item );

        UrisData.push_back( Item );
    } );

    QObject::connect( ButtonUriGroupClear, &QPushButton::clicked, this, [&]()
    {
        for ( auto& uri : UrisData )
            delete uri;

        UrisData.clear();
    } );

    QObject::connect( ButtonHeaderGroupAdd, &QPushButton::clicked, this, [&]()
    {
        auto Item = new QLineEdit;
        Item->setFocus();

        formLayout_Header->setWidget( HeadersData.size(), QFormLayout::FieldRole, Item );

        HeadersData.push_back( Item );
    } );

    QObject::connect( ButtonHeaderGroupClear, &QPushButton::clicked, this, [&]()
    {
        for ( auto& header : HeadersData )
            delete header;

        HeadersData.clear();
    } );

    QObject::connect( ComboPayload, &QComboBox::currentTextChanged, this, [&]( const QString& text )
    {
        if ( text.compare( HavocSpace::Listener::PayloadHTTPS ) == 0 )
        {
            StackWidgetConfigPages->setCurrentIndex( 0 );
            InputPortBind->setText( "443" );
            InputPortConn->setText( "443" );
        }
        else if ( text.compare( HavocSpace::Listener::PayloadHTTP ) == 0 )
        {
            StackWidgetConfigPages->setCurrentIndex( 0 );
            InputPortBind->setText( "80" );
            InputPortConn->setText( "80" );
        }
        else if ( text.compare( HavocSpace::Listener::PayloadSMB ) == 0 )
        {
            StackWidgetConfigPages->setCurrentIndex( 1 );
        }
        else if ( text.compare( HavocSpace::Listener::PayloadExternal ) == 0 )
        {
            StackWidgetConfigPages->setCurrentIndex( 2 );
        }
        else
        {
            for ( const auto& listener : ServiceListeners )
            {
                if ( listener.Name == text.toStdString() )
                {
                    StackWidgetConfigPages->setCurrentIndex( listener.Index );
                    return;
                }
            }

            spdlog::error( "Payload not found" );
        }
    } );

    QObject::connect( CheckEnableProxy, &QCheckBox::toggled, this, &NewListener::onProxyEnabled );

    QMetaObject::connectSlotsByName( Dialog );
}

MapStrStr NewListener::Start( Util::ListenerItem Item, bool Edit )
{
    auto ListenerInfo = MapStrStr();
    auto Payload      = QString();

    if ( Edit )
    {
        InputListenerName->setText( Item.Name.c_str() );
        InputListenerName->setReadOnly( true );

        if ( ( Item.Protocol == Listener::PayloadHTTP.toStdString() ) || ( Item.Protocol == Listener::PayloadHTTPS.toStdString() ) )
        {
            if ( Item.Protocol == Listener::PayloadHTTPS.toStdString() )
                ComboPayload->setCurrentIndex( 0 );
            else
                ComboPayload->setCurrentIndex( 1 );

            ComboPayload->setDisabled( true );

            auto Info = any_cast<Listener::HTTP>( Item.Info );

            ComboHostBind->addItem( Info.HostBind );
            ComboHostBind->setDisabled( true );

            if ( Info.HostRotation.compare( "round-robin" ) == 0 )
                ComboHostRotation->setCurrentIndex( 0 );
            else if ( Info.HostRotation.compare( "random" ) == 0 )
                ComboHostRotation->setCurrentIndex( 1 );
            else
                ComboHostRotation->setCurrentIndex( 0 );

            InputPortBind->setText( Info.PortBind );
            InputPortBind->setReadOnly( true );

            InputPortConn->setText( Info.PortConn );
            InputPortConn->setReadOnly( true );

            InputPSKHttp->setText( Info.PSK );
            InputPSKHttp->setCursorPosition( 0 );

            InputUserAgent->setText( Info.UserAgent );
            InputUserAgent->setCursorPosition( 0 );

            if ( ! Info.Hosts.empty() )
            {
                // Snapshot server IPs once for all host combos in edit mode
                auto ServerIPs = HavocX::Teamserver.IpAddresses;

                for ( const auto& host : Info.Hosts )
                {
                    if ( host.isEmpty() )
                        continue;

                    auto input = new QComboBox;
                    input->setEditable( true );

                    if ( ! ServerIPs.isEmpty() ) {
                        input->addItems( ServerIPs );
                    }

                    // Set the existing host as current value.
                    // If it's a server IP, selects it. If custom, shows it in the edit field.
                    // Works even if ServerIPs was empty (editable combo).
                    input->setCurrentText( host );

                    formLayout_Hosts->setWidget( HostsData.size(), QFormLayout::FieldRole, input );

                    HostsData.push_back( input );
                }
            }

            if ( ! Info.Headers.empty() )
            {
                for ( const auto& header : Info.Headers )
                {
                    if ( header.isEmpty() )
                        continue;

                    auto input = new QLineEdit;
                    input->setText( header );

                    formLayout_Header->setWidget( HeadersData.size(), QFormLayout::FieldRole, input );

                    HeadersData.push_back( input );
                }
            }

            if ( ! Info.Uris.empty() )
            {
                for ( const auto& uri : Info.Uris )
                {
                    if ( uri.isEmpty() )
                        continue;

                    auto input = new QLineEdit;
                    input->setText(uri );

                    formLayout_Uri->setWidget(UrisData.size(), QFormLayout::FieldRole, input );

                    UrisData.push_back(input );
                }
            }

            InputHostHeader->setText( Info.HostHeader );

            if ( Info.ProxyEnabled.compare( "true" ) == 0 )
                CheckEnableProxy->setCheckState( Qt::CheckState::Checked );
            else
                CheckEnableProxy->setCheckState( Qt::CheckState::Unchecked );

            if ( Info.ProxyType.compare( "http" ) == 0 )
                ComboProxyType->setCurrentIndex( 0 );
            else
                ComboProxyType->setCurrentIndex( 1 );

            InputProxyHost->setText( Info.ProxyHost );
            InputProxyPort->setText( Info.ProxyPort );
            InputUserName->setText( Info.ProxyUsername );
            InputPassword->setText( Info.ProxyPassword );
        }
        else if ( Item.Protocol == Listener::PayloadSMB.toStdString() )
        {
            ComboPayload->setCurrentIndex( 2 );
            auto Info = any_cast<Listener::SMB>( Item.Info );

            InputPipeName->setText( Info.PipeName );
            InputPipeName->setReadOnly( true );
            InputPSKSmb->setText( Info.PSK );
            InputPSKSmb->setCursorPosition( 0 );
        }
        else if ( Item.Protocol == Listener::PayloadExternal.toStdString() )
        {
            ComboPayload->setCurrentIndex( 3 );

            auto Info = any_cast<Listener::External>( Item.Info );

            InputEndpoint->setText( Info.Endpoint );
            InputEndpoint->setReadOnly( true );
        }
        else
        {
            // we assume that it's a service listener

            for ( const auto& listener : ServiceListeners )
            {
                if ( listener.Name == Item.Protocol )
                {
                    auto ListenerConfiguration = json::parse( any_cast<Listener::Service>( Item.Info )[ "Info" ] );

                    ComboPayload->setCurrentIndex( listener.Index + 1 );

                    /* TODO: iterate over ServiceListeners and check what has been set
                     *       and blah blah blah just set everything based on the specified object
                     *       and check if its editable etc. */

                    for ( const auto& item : listener.Items )
                    {
                        auto object   = item[ "object" ].get<std::string>();
                        auto editable = item[ "editable" ].get<bool>();
                        auto value    = QString();

                        value = QString( ListenerConfiguration[ item[ "name" ] ].get<std::string>().c_str() );

                        /* if object type is "input" */
                        if ( object == "input" )
                        {
                            auto Line = ( ( QLineEdit* ) item[ "Line" ].get<::uint64_t>() );

                            Line->setText( value );

                            if ( ! editable )
                                Line->setReadOnly( true );
                        }
                    }

                }
            }
        }

        ListenerDialog->setWindowTitle( "Edit Listener" );
        ComboPayload->setDisabled( true );
    }

    ListenerDialog->exec();

    Payload = ComboPayload->currentText();

    ListenerInfo.insert( { "Name",     InputListenerName->text().toStdString() } );
    ListenerInfo.insert( { "Protocol", ComboPayload->currentText().toStdString() } );
    ListenerInfo.insert( { "Status",  "online" } );

    if ( ( Payload.compare( HavocSpace::Listener::PayloadHTTPS ) == 0 ) || ( Payload.compare( HavocSpace::Listener::PayloadHTTP ) == 0 ) )
    {
        auto Hosts   = std::string();
        auto Headers = std::string();
        auto Uris    = std::string();

        if ( Payload.compare( HavocSpace::Listener::PayloadHTTPS ) == 0 )
            ListenerInfo.insert( { "Secure", "true"  } );
        else
            ListenerInfo.insert( { "Secure", "false" } );

        if ( ! HostsData.empty() )
        {
            for ( u32 i = 0; i < HostsData.size(); ++i )
            {
                if ( i == ( HostsData.size() - 1 ) )
                    Hosts += HostsData.at( i )->currentText().toStdString();
                else
                    Hosts += HostsData.at( i )->currentText().toStdString() + ", ";

                delete HostsData.at( i );
            }
        }
        else
        {
            Hosts = ComboHostBind->currentText().toStdString();
        }

        if ( ! HeadersData.empty() )
        {
            for ( u32 i = 0; i < HeadersData.size(); ++i )
            {
                if ( i == ( HeadersData.size() - 1 ) )
                    Headers += HeadersData.at( i )->text().toStdString();
                else
                    Headers += HeadersData.at( i )->text().toStdString() + ", ";

                delete HeadersData.at( i );
            }
        }

        if ( ! UrisData.empty() )
        {
            for ( u32 i = 0; i < UrisData.size(); ++i )
            {
                if ( i == ( UrisData.size() - 1 ) )
                    Uris += UrisData.at( i )->text().toStdString();
                else
                    Uris += UrisData.at( i )->text().toStdString() + ", ";

                delete UrisData.at( i );
            }
        }

        ListenerInfo.insert( { "Hosts", Hosts } );
        ListenerInfo.insert( { "HostBind", ComboHostBind->currentText().toStdString() } );
        ListenerInfo.insert( { "HostRotation", ComboHostRotation->currentText().toStdString() } );
        ListenerInfo.insert( { "PortBind", InputPortBind->text().toStdString() } );
        ListenerInfo.insert( { "PortConn", InputPortConn->text().toStdString() } );
        ListenerInfo.insert( { "PSK", InputPSKHttp->text().toStdString() } );
        ListenerInfo.insert( { "Headers", Headers } );
        ListenerInfo.insert( { "Uris", Uris } );
        ListenerInfo.insert( { "UserAgent", InputUserAgent->text().toStdString() } );
        ListenerInfo.insert( { "HostHeader", InputHostHeader->text().toStdString() } );

        ListenerInfo.insert( { "Proxy Enabled", CheckEnableProxy->isChecked() ? "true" : "false" } );

        if ( CheckEnableProxy->isChecked() )
        {
            ListenerInfo.insert( { "Proxy Type", ComboProxyType->currentText().toStdString() } );
            ListenerInfo.insert( { "Proxy Host", InputProxyHost->text().toStdString() } );
            ListenerInfo.insert( { "Proxy Port", InputProxyPort->text().toStdString() } );
            ListenerInfo.insert( { "Proxy Username", InputUserName->text().toStdString() } );
            ListenerInfo.insert( { "Proxy Password", InputPassword->text().toStdString() } );
        }
    }
    else if ( Payload.compare( HavocSpace::Listener::PayloadSMB ) == 0 )
    {
        ListenerInfo.insert( { "PipeName", InputPipeName->text().toStdString() } );
        ListenerInfo.insert( { "PSK", InputPSKSmb->text().toStdString() } );
    }
    else if ( Payload.compare( HavocSpace::Listener::PayloadExternal ) == 0 )
    {
        for ( auto& Listener : HavocX::Teamserver.Listeners )
        {
            if ( Listener.Protocol == HavocSpace::Listener::PayloadExternal.toStdString() )
            {
                if ( any_cast<HavocSpace::Listener::External>( Listener.Info ).Endpoint.compare( InputEndpoint->text() ) == 0 )
                {
                    MessageBox( "Listener Error", "Listener External: Endpoint already registered.", QMessageBox::Icon::Critical );
                    return MapStrStr{};
                }
            }
        }

        ListenerInfo.insert( { "Endpoint", InputEndpoint->text().toStdString() } );
    }
    else
    {
        for ( const auto& listener : ServiceListeners )
        {
            if ( listener.Name == Payload.toStdString() )
            {
                auto Listener = MapStrStr{
                    { "Name",       InputListenerName->text().toStdString() },
                    { "Protocol",   listener.Name },
                    { "ClientUser", HavocX::Teamserver.User.toStdString() },
                };

                for ( const auto& item : listener.Items )
                {
                    auto object = QString( item[ "object" ].get<std::string>().c_str() );

                    if ( object == "input" )
                    {
                        auto Name = item[ "name" ].get<std::string>();
                        auto Line = ( QLineEdit* ) item[ "Line" ].get<::uint64_t>();

                        Listener.insert( { Name, Line->text().toStdString() } );
                    }
                }

                return Listener;
            }
        }

        spdlog::error( "Payload not found" );

        return {};
    }

    return ListenerInfo;
}

auto NewListener::ListenerCustomAdd( QString Json ) -> bool
{
    if ( Json.isEmpty() )
        return false;

    auto Listener = json::parse( Json.toStdString() );
    auto Page     = ( QWidget* )     nullptr;
    auto Layout   = ( QFormLayout* ) nullptr;
    auto Service  = ServiceListener();

    Page    = new QWidget;
    Layout  = new QFormLayout( Page );
    Service = {
        .Name   = Listener[ "Name" ],
        .Page   = Page,
        .Layout = Layout,
        .Index  = StackWidgetConfigPages->count()
    };

    for ( auto Item : Listener[ "Items" ] )
    {
        if ( Item[ "object" ] == "input" )
        {
            auto Label = new QLabel( Page );
            auto Line  = new QLineEdit( Page );
            auto index = Service.Items.size();

            Label->setText( Item[ "text" ].get<std::string>().c_str() );
            Line->setPlaceholderText( Item[ "placeholder" ].get<std::string>().c_str() );

            Layout->setWidget( index, QFormLayout::LabelRole, Label );
            Layout->setWidget( index, QFormLayout::FieldRole, Line  );

            Service.Items.push_back( {
                { "name",     Item[ "name" ]     },
                { "object",   Item[ "object" ]   },
                { "required", Item[ "required" ] },
                { "editable", Item[ "editable" ] },
                { "Label",    ( uint64_t ) Label },
                { "Line",     ( uint64_t ) Line  },
            } );
        }
    }

    ServiceListeners.push_back( Service );
    ComboPayload->addItem( Service.Name.c_str() );
    StackWidgetConfigPages->addWidget( Page );

    /* check if we already registered this listener */
    for ( auto& x : HavocX::Teamserver.RegisteredListeners )
    {
        if ( x[ "Name" ] == Listener[ "Name" ] )
            return false;
    }

    /* if not then lets add it. */
    HavocX::Teamserver.RegisteredListeners.push_back( Listener );

    return true;
}

void HavocNamespace::UserInterface::Dialogs::NewListener::onButton_Save()
{
    auto Payload = ComboPayload->currentText();

    if ( ( Payload.compare( HavocSpace::Listener::PayloadHTTPS ) == 0 ) ||
         ( Payload.compare( HavocSpace::Listener::PayloadHTTP  ) == 0 ) )
    {
        if ( InputListenerName->text().isEmpty() )
        {
            MessageBox( "Listener Error", "No Listener Name specified", QMessageBox::Critical );

            return;
        }

        if ( InputPortBind->text().isEmpty() )
        {
            MessageBox( "Listener Error", "No PortBind specified", QMessageBox::Critical );

            return;
        }
        else
        {
            if ( ! is_number( InputPortBind->text().toStdString() ) )
            {
                MessageBox( "Listener Error", "PortBind is not a number", QMessageBox::Critical );

                return;
            }
        }

        if ( InputPortConn->text().isEmpty() )
        {
            MessageBox( "Listener Error", "No PortConn specified", QMessageBox::Critical );

            return;
        }
        else
        {
            if ( ! is_number( InputPortConn->text().toStdString() ) )
            {
                MessageBox( "Listener Error", "PortConn is not a number", QMessageBox::Critical );

                return;
            }
        }

        // Auto-generate PSK if empty or too short
        if ( InputPSKHttp->text().isEmpty() || InputPSKHttp->text().size() < 32 )
        {
            QString newPsk = generateRandomPSK();
            InputPSKHttp->setText(newPsk);
            spdlog::info("Auto-generated PSK for HTTP listener: {}", newPsk.toStdString());
        }

        if ( InputUserAgent->text().isEmpty() )
        {
            MessageBox( "Listener Error", "No UserAgent specified", QMessageBox::Critical );

            return;
        }

        if ( CheckEnableProxy->isChecked() )
        {
            if ( InputProxyHost->text().isEmpty() )
            {
                MessageBox( "Listener Error", "No Proxy Host specified", QMessageBox::Critical );

                return;
            }

            if ( InputProxyPort->text().isEmpty() )
            {
                MessageBox( "Listener Error", "No Proxy Port specified", QMessageBox::Critical );

                return;
            }
            else
            {
                if ( ! is_number( InputProxyPort->text().toStdString() ) )
                {
                    MessageBox( "Listener Error", "Port is not a number", QMessageBox::Critical );
                    return;
                }
            }
        }

    }
    else if ( Payload.compare( HavocSpace::Listener::PayloadSMB )  == 0 )
    {
        if ( InputPipeName->text().isEmpty() )
        {
            MessageBox( "Listener Error", "No Pipe name specified", QMessageBox::Critical );

            return;
        }

        // Auto-generate PSK if empty or too short
        if ( InputPSKSmb->text().isEmpty() || InputPSKSmb->text().size() < 32 )
        {
            QString newPsk = generateRandomPSK();
            InputPSKSmb->setText(newPsk);
            spdlog::info("Auto-generated PSK for SMB listener: {}", newPsk.toStdString());
        }
    }
    else if ( Payload.compare( HavocSpace::Listener::PayloadExternal )  == 0 )
    {
        if ( InputEndpoint->text().isEmpty() )
        {
            MessageBox( "Listener Error", "No Endpoint specified", QMessageBox::Critical );

            return;
        }
    }
    else
    {
        for ( const auto& listener : ServiceListeners )
        {
            if ( Payload.compare( listener.Name.c_str() ) == 0 )
            {
                for ( auto item : listener.Items )
                {
                    auto object = item[ "object" ].get<std::string>();

                    /* if object type is "input" */
                    if ( object == "input" )
                    {
                        auto Line = ( ( QLineEdit* ) item[ "Line" ].get<::uint64_t>() );

                        /* if the operator didn't specify a value that is required then let that operator know. */
                        if ( item[ "required" ].get<bool>() && Line->text().isEmpty() )
                        {
                            auto itemName = QString( item[ "name" ].get<std::string>().c_str() );
                            MessageBox( "Listener Error", "No " + itemName + " specified", QMessageBox::Critical );
                            return;
                        }
                    }

                }
            }
        }
    }

    this->DialogSaved = true;
    this->ListenerDialog->close();
}

void HavocNamespace::UserInterface::Dialogs::NewListener::onProxyEnabled()
{
    if ( CheckEnableProxy->isChecked() )
    {
        ProxyConfigBox->setEnabled( true );

        auto style = QString( "color: #f8f8f2;" );
        LabelProxyType->setStyleSheet( style );
        LabelProxyHost->setStyleSheet( style );
        LabelProxyPort->setStyleSheet( style );
        LabelUserName->setStyleSheet( style );
        LabelPassword->setStyleSheet( style );

        InputProxyHost->setReadOnly( false );
        InputProxyPort->setReadOnly( false );
        InputUserName->setReadOnly( false );
        InputPassword->setReadOnly( false );

        LabelProxyHost->setEnabled( false );
        LabelProxyPort->setEnabled( false );
        LabelUserName->setEnabled( false );
        LabelPassword->setEnabled( false );
    }
    else
    {
        ProxyConfigBox->setEnabled( false );

        auto style = QString( "color: #44475a;" );
        LabelProxyType->setStyleSheet( style );
        LabelProxyHost->setStyleSheet( style );
        LabelProxyPort->setStyleSheet( style );
        LabelUserName->setStyleSheet( style );
        LabelPassword->setStyleSheet( style );

        InputProxyHost->setReadOnly( true );
        InputProxyPort->setReadOnly( true );
        InputUserName->setReadOnly( true );
        InputPassword->setReadOnly( true );

        LabelProxyHost->setEnabled( true );
        LabelProxyPort->setEnabled( true );
        LabelUserName->setEnabled( true );
        LabelPassword->setEnabled( true );
    }
}

auto NewListener::Free() -> void
{
    for ( auto listener : ServiceListeners )
    {
        for ( auto item : listener.Items )
        {
            // delete ( QLabel* )    listener.Items[ item ][ "Label" ].get<uint64_t>();
            // delete ( QLineEdit* ) listener.Items[ item ][ "Line"  ].get<uint64_t>();
        }

        delete listener.Layout;
        delete listener.Page;
    }
}

void NewListener::onButton_LoadConfig()
{
    LoadConfigFromFile();
}

auto NewListener::LoadConfigFromFile() -> void
{
    auto FileDialog = QFileDialog();
    auto Filename   = QUrl();
    auto Style      = FileRead( ":/stylesheets/Dialogs/FileDialog" ).toStdString();

    Style.erase( std::remove( Style.begin(), Style.end(), '\n' ), Style.end() );

    FileDialog.setStyleSheet( Style.c_str() );
    FileDialog.setDirectory( QDir::homePath() );
    FileDialog.setNameFilter( "YAOTL Profiles (*.yaotl);;JSON Files (*.json);;All Files (*)" );
    FileDialog.setWindowTitle( "Load Listener Configuration" );

    if ( FileDialog.exec() == QFileDialog::Accepted )
    {
        Filename = FileDialog.selectedUrls().value( 0 ).toLocalFile();
        
        if ( Filename.toString().isEmpty() )
            return;

        QFile file( Filename.toString() );
        if ( !file.open( QIODevice::ReadOnly ) )
        {
            QMessageBox::critical( ListenerDialog, "Error", "Failed to open config file: " + file.errorString() );
            return;
        }
        
        // Validate file size (prevent memory exhaustion)
        qint64 fileSize = file.size();
        if ( fileSize > 10 * 1024 * 1024 )  // 10MB limit
        {
            file.close();
            QMessageBox::critical( ListenerDialog, "Error", "Config file too large (>10MB)" );
            return;
        }

        QByteArray data = file.readAll();
        file.close();
        
        // Validate data is not empty
        if ( data.isEmpty() )
        {
            QMessageBox::critical( ListenerDialog, "Error", "Config file is empty" );
            return;
        }
        
        // Check for null bytes in file data (can cause crashes)
        if ( data.contains('\0') )
        {
            QMessageBox::critical( ListenerDialog, "Error", "Config file contains null bytes - file may be corrupted" );
            return;
        }

        // Convert to QString with validation
        QString fileContent = QString::fromUtf8( data );
        if ( fileContent.isNull() )
        {
            QMessageBox::critical( ListenerDialog, "Error", "Failed to decode file - invalid UTF-8" );
            return;
        }
        
        QString filePath = Filename.toString();

        try
        {
            json config;
            
            // Determine file type and parse accordingly
            if ( filePath.endsWith( ".yaotl", Qt::CaseInsensitive ) )
            {
                // Parse YAOTL format
                config = ParseYAOTLListener( fileContent );
            }
            else
            {
                // Parse JSON format
                config = json::parse( data.toStdString() );
            }
            
            PopulateFieldsFromJson( config );
        }
        catch ( const std::exception& e )
        {
            QMessageBox::critical( ListenerDialog, "Parse Error", 
                QString( "Failed to parse config: %1" ).arg( e.what() ) );
        }
    }
}

auto NewListener::ParseYAOTLListener( const QString& yaotlContent ) -> json
{
    json config;
    
    // Find Listeners block using brace matching (like teamserver does)
    int listenersPos = yaotlContent.indexOf( "Listeners" );
    if ( listenersPos == -1 )
        throw std::runtime_error( "No Listeners block found in YAOTL file" );
    
    int braceStart = yaotlContent.indexOf( '{', listenersPos );
    if ( braceStart == -1 )
        throw std::runtime_error( "Malformed Listeners block" );
    
    // Match braces to find block end
    int depth = 1;
    int pos = braceStart + 1;
    while ( pos < yaotlContent.length() && depth > 0 )
    {
        QChar c = yaotlContent[pos];
        if ( c == '{' ) depth++;
        else if ( c == '}' ) depth--;
        pos++;
    }
    
    // Validate brace matching succeeded
    if ( depth != 0 )
        throw std::runtime_error( "Malformed Listeners block - unmatched braces" );
    
    // Validate substring bounds
    int blockLen = pos - braceStart - 2;
    if ( blockLen <= 0 || pos < braceStart + 2 )
        throw std::runtime_error( "Malformed Listeners block - invalid length" );
    
    QString listenersBlock = yaotlContent.mid( braceStart + 1, blockLen );
    
    // Find listener type (Http, Smb, or External)
    QString listenerType;
    QString listenerBlock;
    
    for ( const QString& type : { "Http", "Smb", "External" } )
    {
        int typePos = listenersBlock.indexOf( type );
        if ( typePos == -1 ) continue;
        
        // Make sure it's the start of a block, not part of another word
        if ( typePos > 0 && listenersBlock[typePos-1].isLetterOrNumber() )
            continue;
        
        int typeBraceStart = listenersBlock.indexOf( '{', typePos );
        if ( typeBraceStart == -1 ) continue;
        
        // Match braces
        depth = 1;
        pos = typeBraceStart + 1;
        while ( pos < listenersBlock.length() && depth > 0 )
        {
            if ( listenersBlock[pos] == '{' ) depth++;
            else if ( listenersBlock[pos] == '}' ) depth--;
            pos++;
        }
        
        // Validate brace matching
        if ( depth != 0 )
            continue;  // Try next listener type
        
        // Validate substring bounds
        int typeBlockLen = pos - typeBraceStart - 2;
        if ( typeBlockLen <= 0 || pos < typeBraceStart + 2 )
            continue;  // Try next listener type
        
        listenerType = type.toLower();
        listenerBlock = listenersBlock.mid( typeBraceStart + 1, typeBlockLen );
        break;
    }
    
    if ( listenerType.isEmpty() )
        throw std::runtime_error( "No valid listener type (Http/Smb/External) found" );
    
    // Check if HTTP is actually HTTPS (like teamserver checks listener.Secure)
    if ( listenerType == "http" )
    {
        QRegularExpression secureRegex( R"(Secure\s*=\s*true)" );
        if ( secureRegex.match( listenerBlock ).hasMatch() )
            listenerType = "https";
    }
    
    config["Type"] = listenerType.toStdString();
    
    // Extract string: Name = "value"
    auto extractString = [&listenerBlock]( const QString& key ) -> QString {
        QRegularExpression regex( key + "\\s*=\\s*\"([^\"]*)\"" );
        QRegularExpressionMatch match = regex.match( listenerBlock );
        return match.hasMatch() ? match.captured( 1 ) : "";
    };
    
    // Extract int: PortBind = 443
    auto extractInt = [&listenerBlock]( const QString& key ) -> int {
        QRegularExpression regex( key + R"(\s*=\s*(\d+))" );
        QRegularExpressionMatch match = regex.match( listenerBlock );
        return match.hasMatch() ? match.captured( 1 ).toInt() : 0;
    };
    
    // Extract array: Hosts = [ "host1", "host2" ]
    auto extractArray = [&listenerBlock]( const QString& key ) -> std::vector<std::string> {
        std::vector<std::string> result;
        
        int keyPos = listenerBlock.indexOf( key );
        if ( keyPos == -1 ) return result;
        
        int arrayStart = listenerBlock.indexOf( '[', keyPos );
        if ( arrayStart == -1 ) return result;
        
        int arrayEnd = listenerBlock.indexOf( ']', arrayStart );
        if ( arrayEnd == -1 ) return result;
        
        QString arrayContent = listenerBlock.mid( arrayStart + 1, arrayEnd - arrayStart - 1 );
        
        // Split by lines and extract quoted strings (handles comments and multiline)
        QStringList lines = arrayContent.split( '\n' );
        for ( const QString& line : lines )
        {
            // Remove # comments
            QString cleanLine = line;
            int commentPos = cleanLine.indexOf( '#' );
            if ( commentPos != -1 )
                cleanLine = cleanLine.left( commentPos );
            
            // Extract "quoted" values
            QRegularExpression itemRegex( "\"([^\"]*)\"" );
            QRegularExpressionMatchIterator it = itemRegex.globalMatch( cleanLine );
            
            while ( it.hasNext() )
            {
                QString item = it.next().captured( 1 ).trimmed();
                if ( !item.isEmpty() )
                    result.push_back( item.toStdString() );
            }
        }
        
        return result;
    };
    
    // Extract all fields (mimics teamserver's listener struct population)
    QString name = extractString( "Name" );
    if ( !name.isEmpty() )
        config["Name"] = name.toStdString();
    
    if ( listenerType == "http" || listenerType == "https" )
    {
        // Mimics: listener.Hosts, listener.HostBind, etc.
        auto hosts = extractArray( "Hosts" );
        if ( !hosts.empty() )
            config["Hosts"] = hosts;
        
        QString hostBind = extractString( "HostBind" );
        if ( !hostBind.isEmpty() )
            config["HostBind"] = hostBind.toStdString();
        
        QString hostRotation = extractString( "HostRotation" );
        if ( !hostRotation.isEmpty() )
            config["HostRotation"] = hostRotation.toStdString();
        
        int portBind = extractInt( "PortBind" );
        if ( portBind > 0 )
            config["PortBind"] = portBind;
        
        int portConn = extractInt( "PortConn" );
        if ( portConn > 0 )
            config["PortConn"] = portConn;

        QString psk = extractString( "PSK" );
        if ( !psk.isEmpty() )
            config["PSK"] = psk.toStdString();
        
        QString userAgent = extractString( "UserAgent" );
        if ( !userAgent.isEmpty() )
            config["UserAgent"] = userAgent.toStdString();
        
        auto headers = extractArray( "Headers" );
        if ( !headers.empty() )
            config["Headers"] = headers;
        
        auto uris = extractArray( "Uris" );
        if ( !uris.empty() )
            config["Uris"] = uris;
        
        // Extract nested Response block (mimics: listener.Response.Headers)
        int responsePos = listenerBlock.indexOf( "Response" );
        if ( responsePos != -1 )
        {
            int responseBraceStart = listenerBlock.indexOf( '{', responsePos );
            if ( responseBraceStart != -1 )
            {
                depth = 1;
                pos = responseBraceStart + 1;
                while ( pos < listenerBlock.length() && depth > 0 )
                {
                    if ( listenerBlock[pos] == '{' ) depth++;
                    else if ( listenerBlock[pos] == '}' ) depth--;
                    pos++;
                }
                
                // Validate brace matching and bounds
                if ( depth != 0 )
                    goto skip_response;  // Skip malformed Response block
                
                int respBlockLen = pos - responseBraceStart - 2;
                if ( respBlockLen <= 0 || pos < responseBraceStart + 2 )
                    goto skip_response;  // Skip invalid Response block
                
                QString responseBlock = listenerBlock.mid( responseBraceStart + 1, respBlockLen );
                
                // Extract Response Headers array
                int respArrayStart = responseBlock.indexOf( '[' );
                if ( respArrayStart != -1 )
                {
                    int respArrayEnd = responseBlock.indexOf( ']', respArrayStart );
                    if ( respArrayEnd != -1 )
                    {
                        QString respArrayContent = responseBlock.mid( respArrayStart + 1, respArrayEnd - respArrayStart - 1 );
                        
                        std::vector<std::string> responseHeaders;
                        QStringList respLines = respArrayContent.split( '\n' );
                        for ( const QString& line : respLines )
                        {
                            QString cleanLine = line;
                            int commentPos = cleanLine.indexOf( '#' );
                            if ( commentPos != -1 )
                                cleanLine = cleanLine.left( commentPos );
                            
                            QRegularExpression itemRegex( "\"([^\"]*)\"" );
                            QRegularExpressionMatchIterator it = itemRegex.globalMatch( cleanLine );
                            
                            while ( it.hasNext() )
                            {
                                QString item = it.next().captured( 1 ).trimmed();
                                if ( !item.isEmpty() )
                                    responseHeaders.push_back( item.toStdString() );
                            }
                        }
                        
                        if ( !responseHeaders.empty() )
                            config["ResponseHeaders"] = responseHeaders;
                    }
                }
            }
        }
        
        skip_response:;  // Label for skipping malformed Response blocks
    }
    else if ( listenerType == "smb" )
    {
        // Mimics: listener.PipeName
        QString pipeName = extractString( "PipeName" );
        if ( !pipeName.isEmpty() )
            config["PipeName"] = pipeName.toStdString();

        QString psk = extractString( "PSK" );
        if ( !psk.isEmpty() )
            config["PSK"] = psk.toStdString();
    }
    else if ( listenerType == "external" )
    {
        // Mimics: listener.Endpoint
        QString endpoint = extractString( "Endpoint" );
        if ( !endpoint.isEmpty() )
            config["Endpoint"] = endpoint.toStdString();
    }
    
    return config;
}

auto NewListener::PopulateFieldsFromJson( const json& config ) -> void
{
    try
    {
        // Validate form layouts exist (CRITICAL - prevents crashes)
        if ( !formLayout_Hosts || !formLayout_Header || !formLayout_Uri )
        {
            QMessageBox::critical( ListenerDialog, "Error", "Internal error: form layouts not initialized" );
            return;
        }
        
        // Set listener name if present
        if ( config.contains( "Name" ) && config["Name"].is_string() )
        {
            std::string nameStr = config["Name"].get<std::string>();
            // Validate no null bytes in string
            if ( nameStr.find('\0') == std::string::npos )
                InputListenerName->setText( QString::fromStdString( nameStr ) );
        }

        // Determine listener type and set appropriate combo box index
        QString listenerType;
        if ( config.contains( "Type" ) && config["Type"].is_string() )
            listenerType = QString::fromStdString( config["Type"].get<std::string>() ).toLower();
        else if ( config.contains( "Secure" ) && config["Secure"].is_boolean() && config["Secure"].get<bool>() )
            listenerType = "https";
        else if ( config.contains( "PortBind" ) && config["PortBind"].is_number() )
            listenerType = "http";
        else if ( config.contains( "PipeName" ) && config["PipeName"].is_string() )
            listenerType = "smb";
        else if ( config.contains( "Endpoint" ) && config["Endpoint"].is_string() )
            listenerType = "external";

        // Set the payload type and switch to appropriate page
        if ( listenerType == "https" )
        {
            ComboPayload->setCurrentText( "Https" );
            StackWidgetConfigPages->setCurrentIndex( 0 );
        }
        else if ( listenerType == "http" )
        {
            ComboPayload->setCurrentText( "Http" );
            StackWidgetConfigPages->setCurrentIndex( 0 );
        }
        else if ( listenerType == "smb" )
        {
            ComboPayload->setCurrentText( "Smb" );
            StackWidgetConfigPages->setCurrentIndex( 1 );
        }
        else if ( listenerType == "external" )
        {
            ComboPayload->setCurrentText( "External" );
            StackWidgetConfigPages->setCurrentIndex( 2 );
        }

        // Populate HTTP/HTTPS fields
        if ( listenerType == "http" || listenerType == "https" )
        {
            // Clear existing hosts
            for ( auto& host : HostsData )
                delete host;
            HostsData.clear();

            // Add hosts from config
            if ( config.contains( "Hosts" ) )
            {
                if ( config["Hosts"].is_array() )
                {
                    for ( const auto& host : config["Hosts"] )
                    {
                        if ( !host.is_string() ) continue;
                        
                        std::string hostStr = host.get<std::string>();
                        // Validate no null bytes
                        if ( hostStr.find('\0') != std::string::npos ) continue;
                        if ( hostStr.empty() ) continue;
                        
                        auto Item = new QComboBox( HostsGroup );
                        Item->setEditable( true );
                        auto ServerIPs = HavocX::Teamserver.IpAddresses;
                        if ( ! ServerIPs.isEmpty() ) {
                            Item->addItems( ServerIPs );
                        }
                        Item->setCurrentText( QString::fromStdString( hostStr ) );
                        formLayout_Hosts->setWidget( HostsData.size(), QFormLayout::FieldRole, Item );
                        HostsData.push_back( Item );
                    }
                }
                else if ( config["Hosts"].is_string() )
                {
                    // Handle comma-separated string
                    std::string hostsStr = config["Hosts"].get<std::string>();
                    // Validate no null bytes
                    if ( hostsStr.find('\0') != std::string::npos ) 
                    {
                        QMessageBox::warning( ListenerDialog, "Warning", "Hosts field contains invalid characters" );
                    }
                    else
                    {
                        std::istringstream iss( hostsStr );
                        std::string host;
                        while ( std::getline( iss, host, ',' ) )
                        {
                            // Trim whitespace safely
                            size_t start = host.find_first_not_of( " \t" );
                            if ( start == std::string::npos ) continue;  // All whitespace
                            
                            size_t end = host.find_last_not_of( " \t" );
                            host = host.substr( start, end - start + 1 );
                            
                            if ( !host.empty() && host.find('\0') == std::string::npos )
                            {
                                auto Item = new QComboBox( HostsGroup );
                                Item->setEditable( true );
                                auto ServerIPs = HavocX::Teamserver.IpAddresses;
                                if ( ! ServerIPs.isEmpty() ) {
                                    Item->addItems( ServerIPs );
                                }
                                Item->setCurrentText( QString::fromStdString( host ) );
                                formLayout_Hosts->setWidget( HostsData.size(), QFormLayout::FieldRole, Item );
                                HostsData.push_back( Item );
                            }
                        }
                    }
                }
            }

            // Set host rotation
            if ( config.contains( "HostRotation" ) && config["HostRotation"].is_string() )
            {
                std::string rotStr = config["HostRotation"].get<std::string>();
                if ( rotStr.find('\0') == std::string::npos )
                    ComboHostRotation->setCurrentText( QString::fromStdString( rotStr ) );
            }

            // Set host bind
            if ( config.contains( "HostBind" ) && config["HostBind"].is_string() )
            {
                std::string bindStr = config["HostBind"].get<std::string>();
                if ( bindStr.find('\0') == std::string::npos )
                    ComboHostBind->setCurrentText( QString::fromStdString( bindStr ) );
            }

            // Set ports (validate they're numbers)
            if ( config.contains( "PortBind" ) && config["PortBind"].is_number_integer() )
            {
                int port = config["PortBind"].get<int>();
                if ( port > 0 && port <= 65535 )
                    InputPortBind->setText( QString::number( port ) );
            }
            
            if ( config.contains( "PortConn" ) && config["PortConn"].is_number_integer() )
            {
                int port = config["PortConn"].get<int>();
                if ( port > 0 && port <= 65535 )
                    InputPortConn->setText( QString::number( port ) );
            }

            if ( config.contains( "PSK" ) && config["PSK"].is_string() )
            {
                std::string pskStr = config["PSK"].get<std::string>();
                if ( pskStr.find('\0') == std::string::npos )
                    InputPSKHttp->setText( QString::fromStdString( pskStr ) );
            }

            // Set user agent
            if ( config.contains( "UserAgent" ) && config["UserAgent"].is_string() )
            {
                std::string uaStr = config["UserAgent"].get<std::string>();
                if ( uaStr.find('\0') == std::string::npos )
                    InputUserAgent->setText( QString::fromStdString( uaStr ) );
            }

            // Clear and add headers
            for ( auto& header : HeadersData )
                delete header;
            HeadersData.clear();

            if ( config.contains( "Headers" ) )
            {
                if ( config["Headers"].is_array() )
                {
                    for ( const auto& header : config["Headers"] )
                    {
                        if ( !header.is_string() ) continue;
                        
                        std::string headerStr = header.get<std::string>();
                        if ( headerStr.find('\0') != std::string::npos ) continue;
                        if ( headerStr.empty() ) continue;
                        
                        auto Item = new QLineEdit( HeadersGroup );
                        Item->setText( QString::fromStdString( headerStr ) );
                        formLayout_Header->setWidget( HeadersData.size(), QFormLayout::FieldRole, Item );
                        HeadersData.push_back( Item );
                    }
                }
                else if ( config["Headers"].is_string() )
                {
                    std::string headersStr = config["Headers"].get<std::string>();
                    if ( headersStr.find('\0') == std::string::npos )
                    {
                        std::istringstream iss( headersStr );
                        std::string header;
                        while ( std::getline( iss, header, ',' ) )
                        {
                            size_t start = header.find_first_not_of( " \t" );
                            if ( start == std::string::npos ) continue;
                            
                            size_t end = header.find_last_not_of( " \t" );
                            header = header.substr( start, end - start + 1 );
                            
                            if ( !header.empty() && header.find('\0') == std::string::npos )
                            {
                                auto Item = new QLineEdit( HeadersGroup );
                                Item->setText( QString::fromStdString( header ) );
                                formLayout_Header->setWidget( HeadersData.size(), QFormLayout::FieldRole, Item );
                                HeadersData.push_back( Item );
                            }
                        }
                    }
                }
            }

            // Clear and add URIs
            for ( auto& uri : UrisData )
                delete uri;
            UrisData.clear();

            if ( config.contains( "Uris" ) )
            {
                if ( config["Uris"].is_array() )
                {
                    for ( const auto& uri : config["Uris"] )
                    {
                        if ( !uri.is_string() ) continue;
                        
                        std::string uriStr = uri.get<std::string>();
                        if ( uriStr.find('\0') != std::string::npos ) continue;
                        if ( uriStr.empty() ) continue;
                        
                        auto Item = new QLineEdit( UrisGroup );
                        Item->setText( QString::fromStdString( uriStr ) );
                        formLayout_Uri->setWidget( UrisData.size(), QFormLayout::FieldRole, Item );
                        UrisData.push_back( Item );
                    }
                }
                else if ( config["Uris"].is_string() )
                {
                    std::string urisStr = config["Uris"].get<std::string>();
                    if ( urisStr.find('\0') == std::string::npos )
                    {
                        std::istringstream iss( urisStr );
                        std::string uri;
                        while ( std::getline( iss, uri, ',' ) )
                        {
                            size_t start = uri.find_first_not_of( " \t" );
                            if ( start == std::string::npos ) continue;
                            
                            size_t end = uri.find_last_not_of( " \t" );
                            uri = uri.substr( start, end - start + 1 );
                            
                            if ( !uri.empty() && uri.find('\0') == std::string::npos )
                            {
                                auto Item = new QLineEdit( UrisGroup );
                                Item->setText( QString::fromStdString( uri ) );
                                formLayout_Uri->setWidget( UrisData.size(), QFormLayout::FieldRole, Item );
                                UrisData.push_back( Item );
                            }
                        }
                    }
                }
            }

            // Set host header
            if ( config.contains( "HostHeader" ) && config["HostHeader"].is_string() )
            {
                std::string hostHeaderStr = config["HostHeader"].get<std::string>();
                if ( hostHeaderStr.find('\0') == std::string::npos )
                    InputHostHeader->setText( QString::fromStdString( hostHeaderStr ) );
            }
        }

        // Populate SMB fields
        if ( listenerType == "smb" )
        {
            if ( config.contains( "PipeName" ) && config["PipeName"].is_string() )
            {
                std::string pipeStr = config["PipeName"].get<std::string>();
                if ( pipeStr.find('\0') == std::string::npos && !pipeStr.empty() )
                    InputPipeName->setText( QString::fromStdString( pipeStr ) );
            }

            if ( config.contains( "PSK" ) && config["PSK"].is_string() )
            {
                std::string pskStr = config["PSK"].get<std::string>();
                if ( pskStr.find('\0') == std::string::npos )
                    InputPSKSmb->setText( QString::fromStdString( pskStr ) );
            }
        }

        // Populate External fields
        if ( listenerType == "external" )
        {
            if ( config.contains( "Endpoint" ) && config["Endpoint"].is_string() )
            {
                std::string endpointStr = config["Endpoint"].get<std::string>();
                if ( endpointStr.find('\0') == std::string::npos && !endpointStr.empty() )
                    InputEndpoint->setText( QString::fromStdString( endpointStr ) );
            }
        }

        QMessageBox::information( ListenerDialog, "Success", "Configuration loaded successfully!" );
    }
    catch ( const std::exception& e )
    {
        QMessageBox::critical( ListenerDialog, "Error", 
            QString( "Failed to populate fields: %1" ).arg( e.what() ) );
    }
}
