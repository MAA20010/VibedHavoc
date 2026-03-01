#include <Havoc/Connector.hpp>
#include <Havoc/Havoc.hpp>
#include <QCryptographicHash>
#include <QMap>
#include <QBuffer>

Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
{
    Teamserver   = ConnectionInfo;
    Socket       = new QWebSocket();
    auto Server  = "wss://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
    auto SslConf = Socket->sslConfiguration();

    /* ignore annoying SSL errors */
    SslConf.setPeerVerifyMode( QSslSocket::VerifyNone );
    Socket->setSslConfiguration( SslConf );
    Socket->ignoreSslErrors();
    
    // Initialize heartbeat timer (30 minutes = 1800000 milliseconds)
    HeartbeatTimer = new QTimer( this );
    HeartbeatTimer->setInterval( 1800000 ); // 30 minutes
    QObject::connect( HeartbeatTimer, &QTimer::timeout, this, &Connector::SendHeartbeat );

    QObject::connect( Socket, &QWebSocket::binaryMessageReceived, this, [this]( const QByteArray& Message )
    {
        //spdlog::info("[CONNECTOR] Received binary message, size: {}", Message.size());
        
        try {
            //spdlog::info("[CONNECTOR] Calling DecodePackage...");
            auto Package = HavocSpace::Packager::DecodePackage( Message );
            
            //spdlog::info("[CONNECTOR] DecodePackage returned: 0x{:x}", reinterpret_cast<uintptr_t>(Package));

            if ( Package != nullptr )
            {
                if ( ! Packager ) {
                    spdlog::warn( "Packager is null, cannot dispatch package" );
                    delete Package; // Prevent memory leak
                    return;
                }

                // Enhanced pointer validation
                uintptr_t addr = reinterpret_cast<uintptr_t>(Package);
                if ( addr < 0x1000 || addr > 0x7fffffffffff ) {
                    spdlog::error( "Invalid Package pointer detected: 0x{:x}", addr );
                    return;
                }
                
                //spdlog::info("[CONNECTOR] Package validated, checking Head.Event...");
                // Validate Package content before accessing
                try {
                    //spdlog::info("[CONNECTOR] Package->Head.Event: {}", Package->Head.Event);
                } catch ( ... ) {
                    spdlog::error("Exception accessing Package->Head.Event, Package corrupted!");
                    return;
                }

                //spdlog::info("[CONNECTOR] Calling DispatchPackage");
                bool result = Packager->DispatchPackage( Package );
                //spdlog::info("[CONNECTOR] DispatchPackage returned: {}", result);
                
                // Clean up the Package after dispatch
                delete Package;
                //spdlog::info("[CONNECTOR] Package deleted successfully");

                return;
            }

            spdlog::critical( "Got Invalid json" );
        } catch ( const std::exception& e ) {
            spdlog::error( "Exception in binaryMessageReceived handler: {}", e.what() );
        } catch ( ... ) {
            spdlog::error( "Unknown exception in binaryMessageReceived handler" );
        }
    } );

    QObject::connect( Socket, &QWebSocket::connected, this, [this]()
    {
        //spdlog::info( "WebSocket connected, initializing Packager..." );
        
        try {
            this->Packager = new HavocSpace::Packager;
            //spdlog::info( "Packager created successfully" );
            
            this->Packager->setTeamserver( this->Teamserver->Name );
            //spdlog::info( "Packager teamserver name set" );

            SendLogin();
            //spdlog::info( "Login credentials sent" );
            
            // Start heartbeat timer to keep session alive
            if ( HeartbeatTimer ) {
                HeartbeatTimer->start();
                //spdlog::info( "[HEARTBEAT] Started 30-minute heartbeat timer" );
            } else {
                spdlog::warn( "[HEARTBEAT] HeartbeatTimer is null, cannot start" );
            }
        } catch ( const std::exception& e ) {
            spdlog::error( "Exception in WebSocket connected handler: {}", e.what() );
        } catch ( ... ) {
            spdlog::error( "Unknown exception in WebSocket connected handler" );
        }
    } );

    QObject::connect( Socket, &QWebSocket::disconnected, this, [this]()
    {
        // Stop heartbeat timer on disconnect
        if ( HeartbeatTimer && HeartbeatTimer->isActive() ) {
            HeartbeatTimer->stop();
            //spdlog::info( "[HEARTBEAT] Stopped heartbeat timer" );
        }
        
        MessageBox( "Teamserver error", Socket->errorString(), QMessageBox::Critical );

        Socket->close();

        Havoc::Exit();
    } );

    Socket->open( QUrl( Server ) );
}

bool Connector::Disconnect()
{
    if ( this->Socket != nullptr )
    {
        this->Socket->disconnect();
        return true;
    }

    return false;
}

Connector::~Connector() noexcept
{
    if ( HeartbeatTimer ) {
        HeartbeatTimer->stop();
        delete HeartbeatTimer;
    }
    delete this->Socket;
}

void Connector::SendLogin()
{
    Util::Packager::Package Package;

    Util::Packager::Head_t Head;
    Util::Packager::Body_t Body;

    Head.Event              = Util::Packager::InitConnection::Type;
    Head.User               = this->Teamserver->User.toStdString();
    Head.Time               = CurrentTime().toStdString();

    Body.SubEvent           = Util::Packager::InitConnection::Login;
    Body.Info[ "User" ]     = this->Teamserver->User.toStdString();
    Body.Info[ "Password" ] = QCryptographicHash::hash( this->Teamserver->Password.toLocal8Bit(), QCryptographicHash::Sha3_256 ).toHex().toStdString();

    Package.Head = Head;
    Package.Body = Body;

    SendPackage( &Package );
}

void Connector::SendPackage( Util::Packager::PPackage Package )
{
    Socket->sendBinaryMessage( Packager->EncodePackage( *Package ).toJson( QJsonDocument::Compact ) );
}

void Connector::SendHeartbeat()
{
    // Send heartbeat to keep session alive (extends session timeout)
    Util::Packager::Package Package;
    Util::Packager::Head_t Head;
    Util::Packager::Body_t Body;

    Head.Event    = Util::Packager::Heartbeat::Type;
    Head.User     = this->Teamserver->User.toStdString();
    Head.Time     = CurrentTime().toStdString();
    Head.OneTime  = "true";  // Don't store ephemeral heartbeats in EventsList

    Body.SubEvent = Util::Packager::Heartbeat::Ping;
    Body.Info[ "Status" ] = "alive";

    Package.Head = Head;
    Package.Body = Body;

    SendPackage( &Package );
    
}
