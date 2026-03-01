#include <global.hpp>

#include <Havoc/Havoc.hpp>
#include <Havoc/Packager.hpp>
#include <Havoc/DemonCmdDispatch.h>
#include <Havoc/Connector.hpp>
#include <Havoc/DBManager/DBManager.hpp>

#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <UserInterface/SmallWidgets/EventViewer.hpp>

#include <cstdint>  // For uintptr_t
#include <UserInterface/Widgets/DemonInteracted.h>
#include <UserInterface/Widgets/ScriptManager.h>
#include <UserInterface/Widgets/ServerLootWidget.h>

#include <Util/ColorText.h>
#include <Util/Base.hpp>

#include <sstream>

#include <QScrollBar>
#include <QByteArray>
#include <QJsonArray>
#include <QDir>
#include <QTimer>
#include <QEventLoop>

const int Util::Packager::InitConnection::Type        = 0x1;
const int Util::Packager::InitConnection::Success     = 0x1;
const int Util::Packager::InitConnection::Error       = 0x2;
const int Util::Packager::InitConnection::Login       = 0x3;
const int Util::Packager::InitConnection::ClientReady = 0x6; 

const int Util::Packager::Listener::Type            = 0x2;
const int Util::Packager::Listener::Add             = 0x1;
const int Util::Packager::Listener::Edit            = 0x2;
const int Util::Packager::Listener::Remove          = 0x3;
const int Util::Packager::Listener::Mark            = 0x4;
const int Util::Packager::Listener::Error           = 0x5;

const int Util::Packager::Chat::Type                = 0x4;
const int Util::Packager::Chat::NewMessage          = 0x1;
const int Util::Packager::Chat::NewListener         = 0x2;
const int Util::Packager::Chat::NewSession          = 0x3;
const int Util::Packager::Chat::NewUser             = 0x4;
const int Util::Packager::Chat::UserDisconnect      = 0x5;

const int Util::Packager::Gate::Type                = 0x5;
const int Util::Packager::Gate::Staged              = 0x1;
const int Util::Packager::Gate::Stageless           = 0x2;

const int Util::Packager::Session::Type             = 0x7;
const int Util::Packager::Session::NewSession       = 0x1;
const int Util::Packager::Session::Remove           = 0x2;
const int Util::Packager::Session::SendCommand      = 0x3;
const int Util::Packager::Session::ReceiveCommand   = 0x4;
const int Util::Packager::Session::MarkAs           = 0x5;

const int Util::Packager::Service::Type             = 0x9;
const int Util::Packager::Service::AgentRegister    = 0x1;
const int Util::Packager::Service::ListenerRegister = 0x2;

const int Util::Packager::Teamserver::Type          = 0x10;
const int Util::Packager::Teamserver::Logger        = 0x1;
const int Util::Packager::Teamserver::Profile       = 0x2;

const int Util::Packager::Loot::Type                = 0x11;
const int Util::Packager::Loot::ListAll             = 0x1;
const int Util::Packager::Loot::ListAgent           = 0x2;
const int Util::Packager::Loot::GetFile             = 0x3;
const int Util::Packager::Loot::SyncAll             = 0x4;
const int Util::Packager::Loot::Delete              = 0x5;

const int Util::Packager::Heartbeat::Type           = 0x12;
const int Util::Packager::Heartbeat::Ping           = 0x1;

using HavocNamespace::UserInterface::Widgets::ScriptManager;

Util::Packager::PPackage Packager::DecodePackage( const QString& Package )
{
    //spdlog::info("[DECODE] Starting DecodePackage with {} bytes", Package.size());
    
    auto FullPackage    = new Util::Packager::Package;
    auto PackageObject  = QJsonObject();
    auto JsonData       = QJsonDocument::fromJson( Package.toUtf8() );
    
    //spdlog::info("[DECODE] Created FullPackage at: 0x{:x}", reinterpret_cast<uintptr_t>(FullPackage));

    if ( JsonData.isEmpty() )
    {
        spdlog::critical( "Invalid json" );
        delete FullPackage;
        return nullptr;
    }

    if ( JsonData.isObject() )
    {
        PackageObject = JsonData.object();

        auto HeadObject = PackageObject[ "Head" ].toObject();
        auto BodyObject = PackageObject[ "Body" ].toObject();

        FullPackage->Head.Event = HeadObject[ "Event" ].toInt();
        FullPackage->Head.Time = HeadObject[ "Time" ].toString().toStdString();
        FullPackage->Head.User = HeadObject[ "User" ].toString().toStdString();

        FullPackage->Body.SubEvent = BodyObject[ "SubEvent" ].toInt();
        
        //spdlog::info("[DECODE] Parsed Event: {}, SubEvent: {}", FullPackage->Head.Event, FullPackage->Body.SubEvent);

        if ( BodyObject[ "Info" ].isObject() )
        {
            foreach( const QString& key, BodyObject[ "Info" ].toObject().keys() )
            {
                FullPackage->Body.Info[ key.toStdString() ] = BodyObject[ "Info" ].toObject().value( key ).toString().toStdString();
            }
        }

    }
    else
    {
        auto object = QJsonDocument( JsonData ).toJson().toStdString();
        spdlog::critical( "Is not an Object: {}", object );
        delete FullPackage;
        return nullptr;
    }
    
    //spdlog::info("[DECODE] Returning FullPackage: 0x{:x}", reinterpret_cast<uintptr_t>(FullPackage));
    return FullPackage;
}

QJsonDocument Packager::EncodePackage( Util::Packager::Package Package )
{
    auto JsonPackage = QJsonObject();
    auto Head        = QJsonObject();
    auto Body        = QJsonObject();
    auto Map         = QVariantMap();
    auto Iterator    = QMapIterator<string, string>( Package.Body.Info );

    while ( Iterator.hasNext() )
    {
        Iterator.next();
        Map.insert( Iterator.key().c_str(), Iterator.value().c_str() );
    }

    Head.insert( "Event", QJsonValue::fromVariant( Package.Head.Event ) );
    Head.insert( "User", QJsonValue::fromVariant( Package.Head.User.c_str() ) );
    Head.insert( "Time", QJsonValue::fromVariant( Package.Head.Time.c_str() ) );
    Head.insert( "OneTime", QJsonValue::fromVariant( Package.Head.OneTime.c_str() ) );

    Body.insert( "SubEvent", QJsonValue::fromVariant( Package.Body.SubEvent ) );
    Body.insert( "Info", QJsonValue::fromVariant( Map ) );

    JsonPackage.insert( "Body", Body );
    JsonPackage.insert( "Head", Head );

    return QJsonDocument( JsonPackage );
}


auto Packager::DispatchPackage( Util::Packager::PPackage Package ) -> bool
{
    // Critical: Validate Package pointer before accessing
    if ( !Package ) {
        spdlog::error( "DispatchPackage called with null Package" );
        return false;
    }
    
    // Additional pointer validation - check if it's in a reasonable memory range
    if ( reinterpret_cast<uintptr_t>(Package) < 0x1000 ) {
        spdlog::error( "DispatchPackage: Invalid Package pointer 0x{:x}", reinterpret_cast<uintptr_t>(Package) );
        return false;
    }
    
    try {
        switch ( Package->Head.Event )
        {
            case Util::Packager::InitConnection::Type:
                return DispatchInitConnection( Package );

            case Util::Packager::Listener::Type:
                return DispatchListener( Package );

            case Util::Packager::Chat::Type:
                return DispatchChat( Package );

            case Util::Packager::Gate::Type:
                return DispatchGate( Package );

            case Util::Packager::Session::Type:
                return DispatchSession( Package );

            case Util::Packager::Service::Type:
                return DispatchService( Package );

            case Util::Packager::Teamserver::Type:
                return DispatchTeamserver( Package );

            case Util::Packager::Loot::Type:
                return DispatchLoot( Package );

            case Util::Packager::Heartbeat::Type:
                // Client-side heartbeat acknowledgment (ephemeral keepalive)
                // Server validates session and extends timeout - no client action needed
                return true;

            default:
                spdlog::info( "[PACKAGE] Event Id not found: {}", Package->Head.Event );
                return false;
        }
    } catch ( const std::exception& e ) {
        spdlog::error( "Exception in DispatchPackage: {}", e.what() );
        return false;
    } catch ( ... ) {
        spdlog::error( "Unknown exception in DispatchPackage" );
        return false;
    }
}

bool Packager::DispatchInitConnection( Util::Packager::PPackage Package )
{
    HavocX::HavocUserInterface = &HavocApplication->HavocAppUI;
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::InitConnection::Success:
        {
            // Store user role from auth response for client-side access control
            if (Package->Body.Info.find("Role") != Package->Body.Info.end()) {
                HavocX::Teamserver.Role = QString::fromStdString(Package->Body.Info["Role"]);
                spdlog::info("User authenticated with role: {}", Package->Body.Info["Role"].c_str());
            } else {
                // Fallback for legacy auth without role
                HavocX::Teamserver.Role = "operator";
                spdlog::warn("No role in auth response, defaulting to operator");
            }
            
            if ( HavocApplication->ClientInitConnect ) {
                //spdlog::info("Starting UI initialization...");
                
                if ( HavocApplication && HavocApplication->HavocMainWindow && ! HavocApplication->HavocAppUI.isVisible() ) {
                    //spdlog::info("Calling setupUi()...");
                    HavocApplication->HavocAppUI.setupUi( HavocApplication->HavocMainWindow );
                    //spdlog::info("setupUi() completed successfully");
                    
                    //spdlog::info("Setting DBManager...");
                    if ( HavocApplication->dbManager ) {
                        HavocApplication->HavocAppUI.setDBManager( HavocApplication->dbManager );
                        //spdlog::info("DBManager set successfully");
                    } else {
                        HavocApplication->HavocAppUI.setDBManager( nullptr );
                        //spdlog::info("DBManager set to nullptr");
                    }
                }

                //spdlog::info("Loading scripts...");
                try {
                    const auto  scripts = toml::find( HavocApplication->Config, "scripts" );
                    const auto& files   = toml::find<std::vector<std::string>>( scripts, "files" );

                    for ( const auto& file : files ) {
                        //spdlog::info("Loading script: {}", file);
                        ScriptManager::AddScript( file.c_str() );
                    }
                    //spdlog::info("All scripts loaded successfully");
                } catch ( const std::exception& e ) {
                    spdlog::warn( "Failed to load scripts: {}", e.what() );
                }

                if ( HavocApplication ) {
                    //spdlog::info("Calling HavocApplication->Start()...");
                    HavocApplication->Start();
                    //spdlog::info("HavocApplication->Start() completed");
                }
                
                //  Delay CLIENT_READY signal to ensure Qt event loop is stable
                // Small delay (150ms) allows all widgets to fully register with Qt's meta-object system
                // Prevents race condition crashes during initialization (observed 1/40 crash rate without delay)
                //spdlog::info("UI initialization complete - scheduling CLIENT_READY signal (150ms delay)");
                
                QTimer::singleShot(150, [this]() {
                    //spdlog::info("Sending CLIENT_READY signal to teamserver");
                    
                    try {
                        Util::Packager::Package readyPackage;
                        Util::Packager::Head_t Head;
                        Util::Packager::Body_t Body;
                        
                        Head.Event   = Util::Packager::InitConnection::Type;
                        Head.User    = "";
                        Head.Time    = "";
                        Head.OneTime = "";
                        
                        Body.SubEvent = Util::Packager::InitConnection::ClientReady;
                        // Body.Info is empty map by default
                        
                        readyPackage.Head = Head;
                        readyPackage.Body = Body;
                        
                        if ( HavocX::Connector ) {
                            HavocX::Connector->SendPackage(&readyPackage);
                            //spdlog::info("CLIENT_READY signal sent successfully");
                        } else {
                            spdlog::error("Cannot send CLIENT_READY - Connector is null");
                        }
                    } catch ( const std::exception& e ) {
                        spdlog::error("Exception sending CLIENT_READY: {}", e.what());
                    } catch ( ... ) {
                        spdlog::error("Unknown exception sending CLIENT_READY");
                    }
                });
            } else {
                if ( HavocApplication ) {
                    HavocApplication->HavocAppUI.NewTeamserverTab( this->TeamserverName );
                    // Update admin tab visibility after auth success
                    HavocApplication->HavocAppUI.UpdateAdminTabVisibility();
                }
                
                //  Delay CLIENT_READY signal for reconnection scenario
                // Same 150ms delay to ensure UI stability before requesting initial state
                //spdlog::info("Reconnection UI setup complete - scheduling CLIENT_READY signal (150ms delay)");
                
                QTimer::singleShot(150, [this]() {
                    //spdlog::info("Sending CLIENT_READY signal to teamserver (reconnection)");
                    
                    try {
                        Util::Packager::Package readyPackage;
                        Util::Packager::Head_t Head;
                        Util::Packager::Body_t Body;
                        
                        Head.Event   = Util::Packager::InitConnection::Type;
                        Head.User    = "";
                        Head.Time    = "";
                        Head.OneTime = "";
                        
                        Body.SubEvent = Util::Packager::InitConnection::ClientReady;
                        // Body.Info is empty map by default
                        
                        readyPackage.Head = Head;
                        readyPackage.Body = Body;
                        
                        if ( HavocX::Connector ) {
                            HavocX::Connector->SendPackage(&readyPackage);
                            //spdlog::info("CLIENT_READY signal sent successfully (reconnection)");
                        } else {
                            spdlog::error("Cannot send CLIENT_READY - Connector is null (reconnection)");
                        }
                    } catch ( const std::exception& e ) {
                        spdlog::error("Exception sending CLIENT_READY (reconnection): {}", e.what());
                    } catch ( ... ) {
                        spdlog::error("Unknown exception sending CLIENT_READY (reconnection)");
                    }
                });
            }

            return true;
        }

        case Util::Packager::InitConnection::Error:
        {
            if ( Package->Body.Info[ "Message" ] == "" ) {
                MessageBox( "Teamserver Error", QString( "Couldn't connect to Teamserver:" + QString( Package->Body.Info[ "Message" ].c_str() ) ), QMessageBox::Critical );
            } else {
                MessageBox( "Teamserver Error", "Couldn't connect to Teamserver", QMessageBox::Critical );
            }

            return true;
        }

        case 0x5:
        {
            auto TeamserverIPs = QString( Package->Body.Info[ "TeamserverIPs" ].c_str() );
            for ( auto& Ip : TeamserverIPs.split( ", " ) ) {
                HavocX::Teamserver.IpAddresses << Ip;
            }

            HavocX::Teamserver.DemonConfig = QJsonDocument::fromJson( Package->Body.Info[ "Demon" ].c_str() );
            
            return true;
        }

        default:
            return false;
    }
}

bool Packager::DispatchListener( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::Listener::Add:
        {
            auto TeamserverTab = HavocX::Teamserver.TabSession;
            
            // CRITICAL: Null check before accessing TabSession widgets
            if ( !TeamserverTab || !TeamserverTab->SmallAppWidgets || !TeamserverTab->SmallAppWidgets->EventViewer ) {
                spdlog::warn("Listener::Add received but TeamserverTab not fully initialized yet - deferring");
                return false;
            }

            // check if this comes from the Teamserver or operator. if from operator then ignore it
            if ( ! Package->Head.User.empty() )
                return false;

            auto ListenerInfo = Util::ListenerItem {
                .Name     = Package->Body.Info[ "Name" ],
                .Protocol = Package->Body.Info[ "Protocol" ],
                .Status   = Package->Body.Info[ "Status" ],
            };

            if ( ListenerInfo.Protocol == Listener::PayloadHTTP.toStdString() )
            {
                auto Headers = QStringList();
                for ( auto& header : QString( Package->Body.Info[ "Headers" ].c_str() ).split( ", " ) ) {
                    Headers << header;
                }

                auto Uris = QStringList();
                for ( auto& uri : QString( Package->Body.Info[ "Uris" ].c_str() ).split( ", " ) ) {
                    Uris << uri;
                }

                auto Hosts = QStringList();
                for ( auto& host : QString( Package->Body.Info[ "Hosts" ].c_str() ).split( ", " ) ) {
                    Hosts << host;
                }

                ListenerInfo.Info = Listener::HTTP {
                    .Hosts          = Hosts,
                    .HostBind       = Package->Body.Info[ "HostBind" ].c_str(),
                    .HostRotation   = Package->Body.Info[ "HostRotation" ].c_str(),
                    .PortBind       = Package->Body.Info[ "PortBind" ].c_str(),
                    .PortConn       = Package->Body.Info[ "PortConn" ].c_str(),
                    .PSK            = Package->Body.Info[ "PSK" ].c_str(),
                    .UserAgent      = Package->Body.Info[ "UserAgent" ].c_str(),
                    .Headers        = Headers,
                    .Uris           = Uris,
                    .HostHeader     = Package->Body.Info[ "HostHeader" ].c_str(),
                    .Secure         = Package->Body.Info[ "Secure" ].c_str(),

                    // proxy configuration
                    .ProxyEnabled   = Package->Body.Info[ "Proxy Enabled" ].c_str(),
                    .ProxyType      = Package->Body.Info[ "Proxy Type" ].c_str(),
                    .ProxyHost      = Package->Body.Info[ "Proxy Host" ].c_str(),
                    .ProxyPort      = Package->Body.Info[ "Proxy Port" ].c_str(),
                    .ProxyUsername  = Package->Body.Info[ "Proxy Username" ].c_str(),
                    .ProxyPassword  = Package->Body.Info[ "Proxy Password" ].c_str(),
                };

                if ( Package->Body.Info[ "Secure" ] == "true" ) {
                    ListenerInfo.Protocol = Listener::PayloadHTTPS.toStdString();
                }
            }
            else if ( ListenerInfo.Protocol == Listener::PayloadSMB.toStdString() )
            {
                ListenerInfo.Info = Listener::SMB {
                    .PipeName = Package->Body.Info[ "PipeName" ].c_str(),
                    .PSK      = Package->Body.Info[ "PSK" ].c_str(),
                };
            }
            else if ( ListenerInfo.Protocol == Listener::PayloadExternal.toStdString() )
            {
                ListenerInfo.Info = Listener::External {
                    .Endpoint = Package->Body.Info[ "Endpoint" ].c_str(),
                };
            }
            else
            {
                // We assume it's a service listener.
                auto found = false;

                for ( const auto& listener : HavocX::Teamserver.RegisteredListeners )
                {
                    if ( ListenerInfo.Protocol == listener[ "Name" ].get<std::string>() )
                    {
                        found = true;

                        ListenerInfo.Info = Listener::Service {
                                { "Host",     Package->Body.Info[ "Host" ].c_str() },
                                { "PortBind", Package->Body.Info[ "Port" ].c_str() },
                                { "PortConn", Package->Body.Info[ "Port" ].c_str() },
                                { "Info",     Package->Body.Info[ "Info" ].c_str() } // NOTE: this is json string.
                        };

                        break;
                    }
                }

                if ( ! found  )
                {
                    spdlog::error( "Listener protocol type not found: {} ", ListenerInfo.Protocol );

                    MessageBox(
                        "Listener Error",
                        QString( ( "Listener protocol type not found: {} " + ListenerInfo.Protocol ).c_str() ),
                        QMessageBox::Critical
                    );

                    return false;
                }
            }

            if ( TeamserverTab->ListenerTableWidget == nullptr )
            {
                TeamserverTab->ListenerTableWidget = new UserInterface::Widgets::ListenersTable;
                TeamserverTab->ListenerTableWidget->setupUi( new QWidget );
                TeamserverTab->ListenerTableWidget->TeamserverName = this->TeamserverName;
            }

            TeamserverTab->ListenerTableWidget->ListenerAdd( ListenerInfo );

            if ( ListenerInfo.Status.compare( "Online" ) == 0 )
            {
                auto MsgStr = "[" + Util::ColorText::Cyan( "*" ) + "]" + " Started " + Util::ColorText::Green( "\"" + QString( ListenerInfo.Name.c_str() ) + "\"" ) + " listener";
                auto Time   = QString( Package->Head.Time.c_str() );

                HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, MsgStr );

                spdlog::info( "Started \"{}\" listener", ListenerInfo.Name );
            }
            else if ( ListenerInfo.Status.compare( "Offline" ) == 0 )
            {
                if ( ! Package->Body.Info[ "Error" ].empty() )
                {
                    auto Error = QString( Package->Body.Info[ "Error" ].c_str() );
                    auto Name  = QString( ListenerInfo.Name.c_str() );

                    TeamserverTab->ListenerTableWidget->ListenerError( Name, Error );
                }
            }

            break;
        }

        case Util::Packager::Listener::Remove:
        {
            // CRITICAL: Null check before accessing TabSession widgets
            if ( !HavocX::Teamserver.TabSession || !HavocX::Teamserver.TabSession->ListenerTableWidget ) {
                spdlog::warn("Listener::Remove received but TeamserverTab not fully initialized yet - deferring");
                return false;
            }

            HavocX::Teamserver.TabSession->ListenerTableWidget->ListenerRemove( Package->Body.Info[ "Name" ].c_str() );

            break;
        }

        case Util::Packager::Listener::Edit:
        {
            // CRITICAL: Null check before accessing TabSession widgets
            if ( !HavocX::Teamserver.TabSession || !HavocX::Teamserver.TabSession->ListenerTableWidget ) {
                spdlog::warn("Listener::Edit received but TeamserverTab not fully initialized yet - deferring");
                return false;
            }
            
            auto ListenerInfo = Util::ListenerItem {
                    .Name     = Package->Body.Info[ "Name" ],
                    .Protocol = Package->Body.Info[ "Protocol" ],
                    .Status   = Package->Body.Info[ "Status" ],
            };

            if ( ListenerInfo.Protocol == Listener::PayloadHTTP.toStdString() )
            {
                auto Headers = QStringList();
                for ( auto& header : QString( Package->Body.Info[ "Headers" ].c_str() ).split( ", " ) )
                    Headers << header;

                auto Uris = QStringList();
                for ( auto& uri : QString( Package->Body.Info[ "Uris" ].c_str() ).split( ", " ) )
                    Uris << uri;

                auto Hosts = QStringList();
                for ( auto& host : QString( Package->Body.Info[ "Hosts" ].c_str() ).split( ", " ) )
                    Hosts << host;


                ListenerInfo.Info = Listener::HTTP {
                        .Hosts          = Hosts,
                        .HostBind       = Package->Body.Info[ "HostBind" ].c_str(),
                        .HostRotation   = Package->Body.Info[ "HostRotation" ].c_str(),
                        .PortBind       = Package->Body.Info[ "PortBind" ].c_str(),
                        .PortConn       = Package->Body.Info[ "PortConn" ].c_str(),
                        .PSK            = Package->Body.Info[ "PSK" ].c_str(),
                        .UserAgent      = Package->Body.Info[ "UserAgent" ].c_str(),
                        .Headers        = Headers,
                        .Uris           = Uris,
                        .HostHeader     = Package->Body.Info[ "HostHeader" ].c_str(),
                        .Secure         = Package->Body.Info[ "Secure" ].c_str(),

                        .ProxyEnabled   = Package->Body.Info[ "Proxy Enabled" ].c_str(),
                        .ProxyType      = Package->Body.Info[ "Proxy Type" ].c_str(),
                        .ProxyHost      = Package->Body.Info[ "Proxy Host" ].c_str(),
                        .ProxyPort      = Package->Body.Info[ "Proxy Port" ].c_str(),
                        .ProxyUsername  = Package->Body.Info[ "Proxy Username" ].c_str(),
                        .ProxyPassword  = Package->Body.Info[ "Proxy Password" ].c_str(),
                };

                if ( Package->Body.Info[ "Secure" ] == "true" )
                {
                    ListenerInfo.Protocol = Listener::PayloadHTTPS.toStdString();
                }

            }
            else if ( ListenerInfo.Protocol == Listener::PayloadSMB.toStdString() )
            {
                ListenerInfo.Info = Listener::SMB {
                        .PipeName = Package->Body.Info[ "PipeName" ].c_str(),
                        .PSK      = Package->Body.Info[ "PSK" ].c_str(),
                };
            }
            else if ( ListenerInfo.Protocol == Listener::PayloadExternal.toStdString() )
            {
                ListenerInfo.Info = Listener::External {
                        .Endpoint = Package->Body.Info[ "Endpoint" ].c_str(),
                };
            }

            HavocX::Teamserver.TabSession->ListenerTableWidget->ListenerEdit( ListenerInfo );

            break;
        }

        case Util::Packager::Listener::Mark:
        {
            break;
        }

        case Util::Packager::Listener::Error:
        {
            // CRITICAL: Null check before accessing TabSession widgets
            if ( !HavocX::Teamserver.TabSession || !HavocX::Teamserver.TabSession->ListenerTableWidget || 
                 !HavocX::Teamserver.TabSession->SmallAppWidgets || !HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer ) {
                spdlog::warn("Listener::Error received but TeamserverTab not fully initialized yet - deferring");
                return false;
            }
            
            auto Error = Package->Body.Info[ "Error" ];
            auto Name  = Package->Body.Info[ "Name" ];

            if ( Package->Head.User.compare( HavocX::Teamserver.User.toStdString() ) == 0 )
            {
                if ( ! Error.empty() )
                {
                    // Show permission errors even without listener name
                    QString errorTitle = Name.empty() ? "Listener Permission Denied" : "Listener Error";
                    MessageBox( errorTitle, QString( Error.c_str() ), QMessageBox::Critical );
                    
                    if ( ! Name.empty() )
                    {
                        HavocX::Teamserver.TabSession->ListenerTableWidget->ListenerError( QString( Name.c_str() ), QString( Error.c_str() ) );

                        auto MsgStr = "[" + Util::ColorText::Red( "-" ) + "]" + " Failed to start " + Util::ColorText::Green( "\"" + QString( Name.c_str() ) + "\"" ) + " listener: " + Util::ColorText::Red( Error.c_str() );
                        auto Time   = QString( Package->Head.Time.c_str() );

                        HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, MsgStr );
                    }
                    else
                    {
                        // Permission error without specific listener name
                        auto MsgStr = "[" + Util::ColorText::Red( "-" ) + "]" + " Listener operation failed: " + Util::ColorText::Red( Error.c_str() );
                        auto Time   = QString( Package->Head.Time.c_str() );

                        HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, MsgStr );
                    }
                }
            }
            else if ( Package->Head.User.empty() )
            {
                if ( ! Name.empty() )
                {
                    if ( ! Error.empty() )
                    {
                        HavocX::Teamserver.TabSession->ListenerTableWidget->ListenerError( QString( Name.c_str() ), QString( Error.c_str() ) );

                        auto MsgStr = "[" + Util::ColorText::Red( "-" ) + "]" + " Failed to start " + Util::ColorText::Green( "\"" + QString( Name.c_str() ) + "\"" ) + " listener: " + Util::ColorText::Red( Error.c_str() );
                        auto Time   = QString( Package->Head.Time.c_str() );

                        HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, MsgStr );
                    }
                }
            }

            break;
        }
    }
    return true;
}

bool Packager::DispatchChat( Util::Packager::PPackage Package)
{
    switch (Package->Body.SubEvent) {
        case Util::Packager::Chat::NewMessage:
        {
            // CRITICAL: Null check before accessing TabSession widgets
            if ( !HavocX::Teamserver.TabSession || !HavocX::Teamserver.TabSession->TeamserverChat ) {
                spdlog::warn("Chat::NewMessage received but TeamserverTab not fully initialized yet - deferring");
                return false;
            }
            
            auto TeamserverUser = HavocX::Teamserver.User;

            for ( const auto& e : Package->Body.Info.toStdMap() )
            {
                auto Time = QString( Package->Head.Time.c_str() );

                HavocX::Teamserver.TabSession->TeamserverChat->AddUserMessage( Time, string( e.first ).c_str(), QByteArray::fromBase64( string( e.second ).c_str() ) );
            }
            break;
        }

        case Util::Packager::Chat::NewListener:
        {
            break;
        }

        case Util::Packager::Chat::NewSession:
        {
            break;
        }

        case Util::Packager::Chat::NewUser:
        {
            // CRITICAL: Null check before accessing TabSession widgets
            if ( !HavocX::Teamserver.TabSession || !HavocX::Teamserver.TabSession->SmallAppWidgets || 
                 !HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer ) {
                spdlog::warn("Chat::NewUser received but TeamserverTab not fully initialized yet - deferring");
                return false;
            }
            
            auto user = QString( Package->Body.Info.toStdMap()[ "User" ].c_str() );
            auto Time = QString( Package->Head.Time.c_str() );

            HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time,  "[" + Util::ColorText::Green( "+" ) + "] " + Util::ColorText::Green( user + " connected to teamserver" ) );
            
            // Update Online Operators widget (with null check for shutdown safety)
            if ( HavocX::Teamserver.TabSession && 
                 HavocX::Teamserver.TabSession->SmallAppWidgets && 
                 HavocX::Teamserver.TabSession->SmallAppWidgets->OnlineOperators ) {
                HavocX::Teamserver.TabSession->SmallAppWidgets->OnlineOperators->onUserConnected( user, Time );
            }

            break;
        }

        case Util::Packager::Chat::UserDisconnect:
        {
            // CRITICAL: Null check before accessing TabSession widgets
            if ( !HavocX::Teamserver.TabSession || !HavocX::Teamserver.TabSession->SmallAppWidgets || 
                 !HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer ) {
                spdlog::warn("Chat::UserDisconnect received but TeamserverTab not fully initialized yet - deferring");
                return false;
            }
            
            auto user = QString( Package->Body.Info.toStdMap()[ "User" ].c_str() );
            auto Time = QString( Package->Head.Time.c_str() );

            HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, "[" + Util::ColorText::Red( "-" ) + "] " + Util::ColorText::Red( user + " disconnected from teamserver" ) );
            
            // Update Online Operators widget (with null check for shutdown safety)
            if ( HavocX::Teamserver.TabSession && 
                 HavocX::Teamserver.TabSession->SmallAppWidgets && 
                 HavocX::Teamserver.TabSession->SmallAppWidgets->OnlineOperators ) {
                HavocX::Teamserver.TabSession->SmallAppWidgets->OnlineOperators->onUserDisconnected( user, Time );
            }

            break;
        }
    }
    return true;
}

bool Packager::DispatchGate( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::Gate::Staged:
        {
            break;
        }

        case Util::Packager::Gate::Stageless:
        {
            // CRITICAL: Null check before accessing TabSession widgets
            if ( !HavocX::Teamserver.TabSession || !HavocX::Teamserver.TabSession->PayloadDialog ) {
                spdlog::warn("Gate::Stageless received but TeamserverTab not fully initialized yet - deferring");
                return false;
            }

            if ( Package->Body.Info[ "PayloadArray" ].size() > 0 )
            {
                auto PayloadArray = QString( Package->Body.Info[ "PayloadArray" ].c_str() ).toLocal8Bit();
                auto FileName     = QString( Package->Body.Info[ "FileName" ].c_str() );

                if (HavocX::GateGUI)
                {
                    HavocX::Teamserver.TabSession->PayloadDialog->ReceivedImplantAndSave( FileName, QByteArray::fromBase64( PayloadArray ) );
                    HavocX::GateGUI = false;
                }
                else
                {
                    if ( HavocX::callbackGate )
                    {
                        PyObject* pyByteArray= PyUnicode_DecodeFSDefault(Package->Body.Info[ "PayloadArray" ].c_str());
                        PyObject* result = PyObject_CallFunctionObjArgs(HavocX::callbackGate, pyByteArray, nullptr);
                        Py_XDECREF(result);
                        Py_XDECREF(pyByteArray);
                    }
                    else
                    {
                        break; // quit if there is no callback
                    }
                }
            }
            else if ( Package->Body.Info[ "MessageType" ].size() > 0  && HavocX::GateGUI)
            {
                auto MessageType = QString( Package->Body.Info[ "MessageType" ].c_str() );
                auto Message     = QString( Package->Body.Info[ "Message" ].c_str() );

                HavocX::Teamserver.TabSession->PayloadDialog->addConsoleLog( MessageType, Message );
            }

            break;
        }
    }
    return true;
}

bool Packager::DispatchSession( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::Session::NewSession:
        {
            auto TeamserverTab = HavocX::Teamserver.TabSession;
            
            // CRITICAL: Null check - TeamserverTab might not be initialized if agent notification
            // arrives before NewTeamserverTab() completes during login
            if ( !TeamserverTab || !TeamserverTab->SessionTableWidget || !TeamserverTab->LootWidget || 
                 !TeamserverTab->SmallAppWidgets || !TeamserverTab->SmallAppWidgets->EventViewer ) {
                spdlog::warn("NewSession received but TeamserverTab not fully initialized yet - deferring");
                return false;
            }
            
            auto MagicValue    = uint64_t( 0 );
            auto StringStream  = std::stringstream();

            StringStream << std::hex << Package->Body.Info[ "MagicValue" ].c_str();
            StringStream >> MagicValue;

            auto Agent = Util::SessionItem {
                    .Name         = Package->Body.Info[ "NameID" ].c_str(),
                    .MagicValue   = MagicValue,
                    .External     = Package->Body.Info[ "ExternalIP" ].c_str(),
                    .Internal     = Package->Body.Info[ "InternalIP" ].c_str(),
                    .Listener     = Package->Body.Info[ "Listener" ].c_str(),
                    .User         = Package->Body.Info[ "Username" ].c_str(),
                    .Computer     = Package->Body.Info[ "Hostname" ].c_str(),
                    .Domain       = Package->Body.Info[ "DomainName" ].c_str(),
                    .OS           = Package->Body.Info[ "OSVersion" ].c_str(),
                    .OSBuild      = Package->Body.Info[ "OSBuild" ].c_str(),
                    .OSArch       = Package->Body.Info[ "OSArch" ].c_str(),
                    .Process      = Package->Body.Info[ "ProcessName" ].c_str(),
                    .PID          = Package->Body.Info[ "ProcessPID" ].c_str(),
                    .Arch         = Package->Body.Info[ "ProcessArch" ].c_str(),
                    .First        = Package->Body.Info[ "FirstCallIn" ].c_str(),
                    .Last         = Package->Body.Info[ "LastCallIn" ].c_str(),
                    .Elevated     = Package->Body.Info[ "Elevated" ].c_str(),
                    .PivotParent  = Package->Body.Info[ "PivotParent" ].c_str(),
                    .Marked       = Package->Body.Info[ "Active" ].c_str(),
                    .SleepDelay   = (uint32_t)strtoul(Package->Body.Info[ "SleepDelay" ].c_str(), NULL, 0),
                    .SleepJitter  = (uint32_t)strtoul(Package->Body.Info[ "SleepJitter" ].c_str(), NULL, 0),
                    .KillDate     = (uint64_t)strtoull(Package->Body.Info[ "KillDate" ].c_str(), NULL, 0),
                    .WorkingHours = (uint32_t)strtoul(Package->Body.Info[ "WorkingHours" ].c_str(), NULL, 0),
            };

            Agent.LastUTC = QDateTime::fromString(Agent.Last, "dd-MM-yyyy HH:mm:ss");

            if ( Agent.Marked == "true" )
            {
                Agent.Marked = "Alive";
                Agent.Health = "healthy";
            }
            else if ( Agent.Marked == "false" )
            {
                Agent.Marked = "Dead";
                Agent.Health = "dead";
            }

            for ( auto& session : HavocX::Teamserver.Sessions )
                if ( session.Name.compare( Agent.Name ) == 0 )
                    return false;

            TeamserverTab->SessionTableWidget->NewSessionItem( Agent );
            TeamserverTab->LootWidget->AddSessionSection( Agent.Name );

            auto Time    = QString( Package->Head.Time.c_str() );
            auto Message = "[" + Util::ColorText::Cyan( "*" ) + "]" + " Initialized " + Util::ColorText::Cyan( Agent.Name ) + " :: " + Util::ColorText::Yellow( Agent.User + "@" + Agent.Internal ) + Util::ColorText::Cyan( " (" ) + Util::ColorText::Red( Agent.Computer ) + Util::ColorText::Cyan( ")" );

            HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, Message );

            if ( Agent.Marked.compare( "Alive" ) == 0 )
            {
                for ( auto& Callback : HavocX::Teamserver.RegisteredCallbacks )
                {
                    if ( PyCallable_Check( Callback ) )
                    {
                        PyObject* arglist = Py_BuildValue( "s", Agent.Name.toStdString().c_str() );
                        PyObject* Return  = PyObject_CallFunctionObjArgs( Callback, arglist, NULL );
                        if ( Return == NULL && PyErr_Occurred() )
                        {
                            spdlog::error( "Error calling callback" );
                            PyErr_PrintEx(0);
                            PyErr_Clear();
                        }
                        Py_XDECREF(Return);
                        Py_DECREF(arglist);
                    } else {
                        spdlog::error( "Callback is not callable" );
                    }
                }
            }

            break;
        }

        case Util::Packager::Session::SendCommand:
        {
            for ( auto& Session : HavocX::Teamserver.Sessions )
            {
                if ( Session.Name.compare( Package->Body.Info[ "DemonID" ].c_str() ) == 0 )
                {
                    auto AgentType = QString( Package->Body.Info[ "AgentType" ].c_str() );

                    if ( ! Package->Body.Info[ "CommandLine" ].empty() )
                    {
                        auto TaskID = QString( Package->Body.Info[ "TaskID" ].c_str() );

                        if ( AgentType.isEmpty() )
                            AgentType = "Demon";

                        Session.InteractedWidget->DemonCommands->Prompt = QString (
                                Util::ColorText::Comment( QString( Package->Head.Time.c_str() ) + " [" + QString( Package->Head.User.c_str() ) + "]" ) +
                                " " + Util::ColorText::UnderlinePink( AgentType ) +
                                Util::ColorText::Cyan(" » ") + QString( Package->Body.Info[ "CommandLine" ].c_str() )
                        );

                        if ( ! Package->Body.Info[ "TaskMessage" ].empty() )
                        {
                            Session.InteractedWidget->DemonCommands->CommandTaskInfo[ TaskID ] = Package->Body.Info[ "TaskMessage" ].c_str();
                        }
                        else
                        {
                            Session.InteractedWidget->AppendRaw();
                            Session.InteractedWidget->AppendRaw( Session.InteractedWidget->DemonCommands->Prompt );
                        }

                        Session.InteractedWidget->lineEdit->AddCommand( QString( Package->Body.Info[ "CommandLine" ].c_str() ) );
                        Session.InteractedWidget->DemonCommands->DispatchCommand( false, TaskID, Package->Body.Info[ "CommandLine" ].c_str() );
                    }
                }
            }
            break;
        }

        case Util::Packager::Session::ReceiveCommand:
        {
            for ( auto & Session : HavocX::Teamserver.Sessions )
            {
                if ( Session.Name.compare( Package->Body.Info[ "DemonID" ].c_str() ) == 0 )
                {
                    Session.InteractedWidget->DemonCommands->OutputDispatch.DemonCommandInstance = Session.InteractedWidget->DemonCommands;

                    int CommandID = QString( Package->Body.Info[ "CommandID" ].c_str() ).toInt();
                    auto Output   = QString( Package->Body.Info[ "Output" ].c_str() );

                    switch ( CommandID )
                    {
                        case ( int ) Commands::CONSOLE_MESSAGE:

                            if ( QByteArray::fromBase64( Output.toLocal8Bit() ).length() > 5 )
                            {
                                Session.InteractedWidget->DemonCommands->OutputDispatch.MessageOutput(
                                        Output,
                                        QString( Package->Head.Time.c_str() )
                                );
                                Session.InteractedWidget->Console->verticalScrollBar()->setValue(
                                        Session.InteractedWidget->Console->verticalScrollBar()->maximum()
                                );
                            }

                            break;

                        case ( int ) Commands::BOF_CALLBACK:

                            if ( QByteArray::fromBase64( Output.toLocal8Bit() ).length() > 5 )
                            {
                                auto JsonDocument  = QJsonDocument::fromJson( QByteArray::fromBase64( Output.toLocal8Bit( ) ) );
                                auto Worked        = JsonDocument[ "Worked" ].toString();
                                auto Output        = JsonDocument[ "Output" ].toString();
                                auto Error         = JsonDocument[ "Error"  ].toString();
                                auto TaskID        = JsonDocument[ "TaskID" ].toString();
                                PyObject* Callback = nullptr;

                                auto it = Session.TaskIDToPythonCallbacks.find( TaskID );
                                if ( it != Session.TaskIDToPythonCallbacks.end() ) {
                                    Callback = it->second;
                                    if ( PyCallable_Check( Callback ) )
                                    {
                                        PyObject *arglist = Py_BuildValue( "ssOss", Session.Name.toStdString().c_str(), TaskID.toStdString().c_str(), Worked == "true" ? Py_True : Py_False, Output.toStdString().c_str(), Error.toStdString().c_str() );
                                        PyObject* result = PyObject_CallObject( Callback, arglist );
                                        Py_XDECREF(result);
                                        Py_DECREF(arglist);
                                        Py_XDECREF( Callback );
                                    } else {
                                        spdlog::error( "Callback is not callable" );
                                    }

                                    Session.TaskIDToPythonCallbacks.erase( TaskID );

                                    // print messages from the python the module
                                    Session.InteractedWidget->DemonCommands->PrintModuleCachedMessages();
                                } else {
                                    auto taskId = TaskID.toStdString();
                                    spdlog::error( "[PACKAGE] TaskID not found: {}", taskId );
                                }
                            }

                            break;

                        case ( int ) Commands::CALLBACK:
                        {
                            // update the "Last" field on this session
                            auto LastTime     = QString( QByteArray::fromBase64( Output.toLocal8Bit() ) );
                            auto LastTimeJson = QJsonDocument::fromJson( LastTime.toLocal8Bit() );

                            Session.Last         = LastTimeJson["Last"].toString();
                            Session.LastUTC      = QDateTime::fromString(Session.Last, "dd-MM-yyyy HH:mm:ss");
                            Session.SleepDelay   = (uint32_t)strtoul(LastTimeJson["Sleep"].toString().toStdString().c_str(), NULL, 0);
                            Session.SleepJitter  = (uint32_t)strtoul(LastTimeJson["Jitter"].toString().toStdString().c_str(), NULL, 0);
                            Session.KillDate     = (uint64_t)strtoull(LastTimeJson["KillDate"].toString().toStdString().c_str(), NULL, 0);
                            Session.WorkingHours = (uint32_t)strtoul(LastTimeJson["WorkingHours"].toString().toStdString().c_str(), NULL, 0);
                            break;
                        }

                        default:
                            spdlog::error( "[PACKAGE] Command not found" );
                            break;
                    }

                    break;
                }
            }

            break;
        }

        case Util::Packager::Session::Remove:
        {
            break;
        }

        case Util::Packager::Session::MarkAs:
        {
            // CRITICAL: Null check before accessing TabSession widgets
            if ( !HavocX::Teamserver.TabSession || !HavocX::Teamserver.TabSession->SessionTableWidget || 
                 !HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget ) {
                spdlog::warn("Session::MarkAs received but TeamserverTab not fully initialized yet - deferring");
                return false;
            }
            
            auto AgentID = Package->Body.Info[ "AgentID" ];
            auto Marked  = Package->Body.Info[ "Marked" ];

            for ( auto& session : HavocX::Teamserver.Sessions )
            {
                if ( session.Name.toStdString() == AgentID )
                {
                    session.Marked = Marked.c_str();
                    break;
                }
            }

            for ( int i = 0; i < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->rowCount(); i++ )
            {
                auto Row = HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->text();

                if ( Row.compare( QString( AgentID.c_str() ) ) == 0 )
                {
                    if ( Marked.compare( "Alive" ) == 0 )
                    {
                        for ( auto& session : HavocX::Teamserver.Sessions )
                        {
                            if ( session.Name.toStdString() == AgentID )
                            {
                                auto Icon = ( session.Elevated.compare( "true" ) == 0 ) ?
                                        WinVersionIcon( session.OS, true ) :
                                        WinVersionIcon( session.OS, false );

                                HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->setIcon( Icon );

                                break;
                            }
                        }

                        for ( int j = 0; j < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->columnCount(); j++ )
                        {
                            HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::Background ) );
                            HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Foreground ) );
                        }
                    }
                    else if ( Marked.compare( "Dead" ) == 0 )
                    {
                        HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->setIcon( QIcon( ":/icons/DeadWhite" ) );

                        for ( int j = 0; j < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->columnCount(); j++ )
                        {
                            HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::CurrentLine ) );
                            HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Comment ) );
                        }
                    }

                    break;
                }
            }

            break;
        }
    }
    return true;
}

bool Packager::DispatchService( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::Service::AgentRegister:
        {
            auto JsonObject     = QJsonDocument::fromJson( Package->Body.Info[ "Agent" ].c_str() ).object();
            auto OSArray        = QStringList();
            auto Arch           = QStringList();
            auto Formats        = std::vector<AgentFormat>();
            auto Commands       = std::vector<AgentCommands>();
            auto MagicValue     = uint64_t( 0 );
            auto StringStream   = std::stringstream();
            auto AgentName      = std::string();

            for ( const auto& item : JsonObject[ "Arch" ].toArray() )
                Arch << item.toString();

            for ( const auto& item : JsonObject[ "Formats" ].toArray() )
            {
                Formats.push_back( AgentFormat {
                        .Name = item.toObject()[ "Name" ].toString(),
                        .Extension = item.toObject()[ "Extension" ].toString(),
                } );
            }

            for ( const auto& item : JsonObject[ "SupportedOS" ].toArray() )
                OSArray << item.toString();

            for ( const auto& command : JsonObject[ "Commands" ].toArray() )
            {
                auto Mitr   = QStringList();
                auto Params = std::vector<CommandParam>();

                for ( const auto& param : command.toObject()[ "Params" ].toArray() )
                {
                    Params.push_back( CommandParam {
                        .Name       = param.toObject()[ "Name" ].toString(),
                        .IsFilePath = param.toObject()[ "IsFilePath" ].toBool(),
                        .IsOptional = param.toObject()[ "IsOptional" ].toBool(),
                    } );
                }

                for ( const auto& i : command.toObject()[ "Mitr" ].toArray() )
                    Mitr << i.toString();

                Commands.push_back( AgentCommands{
                    .Name        = command.toObject()[ "Name" ].toString(),
                    .Description = command.toObject()[ "Description" ].toString(),
                    .Help        = command.toObject()[ "Help" ].toString(),
                    .NeedAdmin   = command.toObject()[ "NeedAdmin" ].toBool(),
                    .Mitr        = Mitr,
                    .Params      = Params,
                    .Anonymous   = command.toObject()[ "Anonymous" ].toBool(),
                } );
            }

            StringStream << std::hex << JsonObject[ "MagicValue" ].toString().toStdString();
            StringStream >> MagicValue;

            HavocX::Teamserver.ServiceAgents.push_back( ServiceAgent{
                .Name           = JsonObject[ "Name" ].toString(),
                .Description    = JsonObject[ "Description" ].toString(),
                .Version        = JsonObject[ "Version" ].toString(),
                .MagicValue     = MagicValue,
                .Arch           = Arch,
                .Formats        = Formats,
                .SupportedOS    = OSArray,
                .Commands       = Commands,
                .BuildingConfig = QJsonDocument( JsonObject[ "BuildingConfig" ].toObject() ),
            } );

            AgentName = JsonObject[ "Name" ].toString().toStdString();

            spdlog::info( "Added service agent to client: {}", AgentName );

            return true;
        }

        case Util::Packager::Service::ListenerRegister:
        {
            auto listener = json::parse( Package->Body.Info[ "Listener" ].c_str() );
            auto name     = listener[ "Name" ].get<std::string>();

            HavocX::Teamserver.RegisteredListeners.push_back( listener );

            spdlog::info( "Added service listener to client: {}", name );

            return true;
        }

        default: break;
    }
    return false;
}

bool Packager::DispatchTeamserver( Util::Packager::PPackage Package )
{
    // Critical: Validate Package and Body before accessing SubEvent
    if ( !Package ) {
        //spdlog::error( "DispatchTeamserver called with null Package" );
        return false;
    }
    
    // Additional validation to prevent memory corruption
    if ( reinterpret_cast<uintptr_t>(Package) < 0x1000 ) {
        //spdlog::error( "DispatchTeamserver: Invalid Package pointer 0x{:x}", reinterpret_cast<uintptr_t>(Package) );
        return false;
    }
    
    // Log before accessing Body.SubEvent to identify crash point
    //spdlog::info( "[DISPATCH] DispatchTeamserver: Package=0x{:x}, about to access SubEvent", reinterpret_cast<uintptr_t>(Package) );
    
    int subEvent;
    try {
        // Safely access SubEvent with exception handling
        subEvent = Package->Body.SubEvent;
        //spdlog::info( "[DISPATCH] DispatchTeamserver: SubEvent={}", subEvent );
    } catch ( const std::exception& e ) {
        spdlog::error( "Exception accessing Package->Body.SubEvent: {}", e.what() );
        return false;
    } catch ( ... ) {
        spdlog::error( "Unknown exception accessing Package->Body.SubEvent" );
        return false;
    }
    
    switch ( subEvent )
    {
        case Util::Packager::Teamserver::Logger:
        {
            try {
                //spdlog::info( "[DISPATCH] Logger: Starting handler for Package=0x{:x}", reinterpret_cast<uintptr_t>(Package) );
                
                // Step 1: Validate Info map access
                //spdlog::info( "[DISPATCH] Logger: About to access Package->Body.Info[\"Text\"]" );
                
                if ( !Package->Body.Info.contains("Text") ) {
                    //spdlog::error( "[DISPATCH] Logger: 'Text' key not found in Package->Body.Info" );
                    return false;
                }
                
                const std::string& textStr = Package->Body.Info["Text"];
                //spdlog::info( "[DISPATCH] Logger: Got text string, length: {}", textStr.length() );
                
                // Step 2: Convert to QString
                //spdlog::info( "[DISPATCH] Logger: About to create QString from text" );
                auto Text = QString( textStr.c_str() );
                //spdlog::info( "[DISPATCH] Logger: QString created successfully" );

                // Step 3: Check TabSession pointer (now properly initialized to nullptr)
                //spdlog::info( "[DISPATCH] Logger: Checking HavocX::Teamserver.TabSession pointer" );
                if ( HavocX::Teamserver.TabSession == nullptr ) {
                    //spdlog::warn( "[DISPATCH] Logger: HavocX::Teamserver.TabSession is null - UI not ready yet, silently dropping Logger event" );
                    return true;  // Return true to acknowledge processing (silently drop)
                }
                //spdlog::info( "[DISPATCH] Logger: TabSession pointer is valid: {}", static_cast<void*>(HavocX::Teamserver.TabSession) );
                
                // Step 4: Check Teamserver pointer - CRITICAL VALIDATION
                //spdlog::info( "[DISPATCH] Logger: TabSession validated, checking Teamserver pointer" );
                
                // Use try-catch for ALL TabSession->Teamserver operations since they crash
                Teamserver* teamserverPtr = nullptr;
                try {
                    //spdlog::info( "[DISPATCH] Logger: About to access TabSession->Teamserver" );
                    teamserverPtr = HavocX::Teamserver.TabSession->Teamserver;
                    //spdlog::info( "[DISPATCH] Logger: TabSession->Teamserver accessed, ptr: {}", 
                        static_cast<void*>(teamserverPtr);
                        
                    // CRITICAL: Check for obviously invalid pointer values
                    uintptr_t ptrValue = reinterpret_cast<uintptr_t>(teamserverPtr);
                    if ( ptrValue < 0x10000 ) {  // Any pointer below 64KB is clearly invalid
                        //spdlog::error( "[DISPATCH] Logger: INVALID pointer value: 0x{:x} - too small to be valid heap", ptrValue );
                        teamserverPtr = nullptr;  // Force to null to trigger recreation
                    }
                    
                } catch ( const std::exception& e ) {
                    //spdlog::error( "[DISPATCH] Logger: Exception accessing TabSession->Teamserver: {}", e.what() );
                    return false;
                } catch ( ... ) {
                    //spdlog::error( "[DISPATCH] Logger: Unknown exception accessing TabSession->Teamserver" );
                    return false;
                }
                
                if ( teamserverPtr == nullptr )
                {
                    //spdlog::info( "[DISPATCH] Logger: Creating new Teamserver instance" );
                    try {
                        teamserverPtr = new Teamserver;
                        HavocX::Teamserver.TabSession->Teamserver = teamserverPtr;
                        //spdlog::info( "[DISPATCH] Logger: About to call setupUi" );
                        teamserverPtr->setupUi( new QDialog );
                        //spdlog::info( "[DISPATCH] Logger: setupUi completed" );
                    } catch ( const std::exception& e ) {
                        //spdlog::error( "[DISPATCH] Logger: Exception creating Teamserver: {}", e.what() );
                        return false;
                    } catch ( ... ) {
                        //spdlog::error( "[DISPATCH] Logger: Unknown exception creating Teamserver" );
                        return false;
                    }
                }

                // Step 5: Add logger text - CRITICAL VALIDATION WITH SAFE POINTER
                try {
                    if ( teamserverPtr->TeamserverLogger == nullptr ) {
                        //spdlog::error( "[DISPATCH] Logger: CRITICAL - TeamserverLogger is NULL, aborting" );
                        return false;
                    }
                    
                    //spdlog::info( "[DISPATCH] Logger: TeamserverLogger validated: {}", 
                        static_cast<void*>(teamserverPtr->TeamserverLogger);
                    
                    //spdlog::info( "[DISPATCH] Logger: About to call AddLoggerText" );
                    teamserverPtr->AddLoggerText( Text );
                    //spdlog::info( "[DISPATCH] Logger: AddLoggerText completed successfully" );
                } catch ( const std::exception& e ) {
                    //spdlog::error( "[DISPATCH] Logger: Exception in AddLoggerText: {}", e.what() );
                    return false;
                } catch ( ... ) {
                    //spdlog::error( "[DISPATCH] Logger: Unknown exception in AddLoggerText" );
                    return false;
                }
                
            } catch ( const std::exception& e ) {
                //spdlog::error( "Exception in Teamserver::Logger handler: {}", e.what() );
                return false;
            }
            break; // CRITICAL: Added missing break statement
        }

        case Util::Packager::Teamserver::Profile:
        {
            // TODO: Implement Profile handler
            //spdlog::info( "[DISPATCH] Teamserver::Profile handler not implemented" );
            break; // CRITICAL: Missing break statement
        }
        
        default:
        {
            //spdlog::warn( "[DISPATCH] Unknown Teamserver SubEvent: {}", subEvent );
            return false;
        }
    }
    return true;
}

bool Packager::DispatchLoot( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::Loot::SyncAll:
        {
            // Handle full loot synchronization from server
            if ( Package->Body.Info.contains( "LootData" ) )
            {
                auto LootDataJson = QString::fromStdString( Package->Body.Info["LootData"] );
                
                try {
                    // Clear existing server loot before adding new items
                    if ( HavocX::Teamserver.TabSession->ServerLootWidget != nullptr ) {
                        HavocX::Teamserver.TabSession->ServerLootWidget->ClearLoot();
                    }
                    
                    auto JsonDocument = QJsonDocument::fromJson( LootDataJson.toUtf8() );
                    auto LootIndices = JsonDocument.array();
                    
                    // Process each agent's loot index
                    for ( const auto& indexValue : LootIndices )
                    {
                        auto indexObj = indexValue.toObject();
                        auto agentID = indexObj["agent_id"].toString();
                        auto items = indexObj["items"].toArray();
                        
                        // Add each loot item to the ServerLootWidget
                        for ( const auto& itemValue : items )
                        {
                            auto item = itemValue.toObject();
                            auto type = item["type"].toString();
                            auto fileName = item["filename"].toString();
                            auto timestamp = item["timestamp"].toString();
                            auto operator_name = item["operator"].toString();
                            auto relativePath = item["relative_path"].toString();
                            auto size = item["size"].toInt();
                            auto externalIP = item["external_ip"].toString();
                            auto hostname = item["hostname"].toString();
                            auto sessionID = item["session_id"].toString();
                            
                            // Route to ServerLootWidget if it exists
                            if ( HavocX::Teamserver.TabSession->ServerLootWidget != nullptr ) {
                                if ( type == "screenshot" )
                                {
                                    HavocX::Teamserver.TabSession->ServerLootWidget->AddServerSideScreenshot( 
                                        agentID, fileName, timestamp, relativePath, 
                                        operator_name.isEmpty() ? "unknown" : operator_name,
                                        externalIP.isEmpty() ? "N/A" : externalIP,
                                        hostname.isEmpty() ? "N/A" : hostname,
                                        sessionID.isEmpty() ? agentID : sessionID
                                    );
                                }
                                else if ( type == "download" )
                                {
                                    auto sizeStr = QString::number( size );
                                    HavocX::Teamserver.TabSession->ServerLootWidget->AddServerSideDownload( 
                                        agentID, fileName, sizeStr, timestamp, relativePath,
                                        operator_name.isEmpty() ? "unknown" : operator_name,
                                        externalIP.isEmpty() ? "N/A" : externalIP,
                                        hostname.isEmpty() ? "N/A" : hostname,
                                        sessionID.isEmpty() ? agentID : sessionID
                                    );
                                }
                            }
                        }
                    }
                    
                } catch ( ... ) {
                    spdlog::error( "Failed to parse loot data from server" );
                }
            }
            break;
        }
        
        case Util::Packager::Loot::ListAgent:
        {
            // Handle individual agent loot data (similar to SyncAll but for one agent)
            // This could be used for on-demand loading
            break;
        }
        
        case Util::Packager::Loot::GetFile:
        {
            // Handle server loot file response for ServerLootWidget
            if ( Package->Body.Info.contains( "FileData" ) && Package->Body.Info.contains( "AgentID" ) && Package->Body.Info.contains( "RelativePath" ) )
            {
                auto AgentID = QString::fromStdString( Package->Body.Info["AgentID"] );
                auto RelativePath = QString::fromStdString( Package->Body.Info["RelativePath"] );
                auto FileDataBase64 = QString::fromStdString( Package->Body.Info["FileData"] );
                auto FileData = QByteArray::fromBase64( FileDataBase64.toUtf8() );
                
                // Update ServerLootWidget if it exists
                if ( HavocX::Teamserver.TabSession->ServerLootWidget != nullptr ) {
                    HavocX::Teamserver.TabSession->ServerLootWidget->UpdateServerLootFileResponse( AgentID, RelativePath, FileData );
                }
            }
            break;
        }
        
        default:
            spdlog::info( "[LOOT] Unknown SubEvent: {}", Package->Body.SubEvent );
            return false;
    }
    
    return true;
}

void Packager::setTeamserver( QString Name )
{
    this->TeamserverName = Name;
}
