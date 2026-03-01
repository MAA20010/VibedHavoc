#include <Havoc/Havoc.hpp>
#include <Havoc/Connector.hpp>
#include <Havoc/CmdLine.hpp>

#include <QTimer>
#include <QEventLoop>

HavocSpace::Havoc::Havoc( QMainWindow* w )
{
    w->setVisible( false );

    spdlog::set_pattern( "[%T] [%^%l%$] %v" );
    spdlog::info(
        "Havoc Framework [Version: {}] [CodeName: {}]",
        HavocNamespace::Version,
        HavocNamespace::CodeName
    );

    this->HavocMainWindow = w;
    
    // Critical: DBManager creation with retry mechanism to handle Qt SQL subsystem initialization failures
    // The QSqlDatabase::addDatabase() call can fail with epoll_ctl EPERM errors on some systems
    this->dbManager = nullptr;
    for (int attempt = 1; attempt <= 5; attempt++) {
        spdlog::info("[DBManager] Initialization attempt {} of 5", attempt);
        
        try {
            this->dbManager = new HavocSpace::DBManager( "data/client.db", DBManager::CreateSqlFile );
            if (this->dbManager) {
                spdlog::info("[DBManager] Successfully initialized on attempt {}", attempt);
                break;
            }
        } catch (const std::exception& e) {
            spdlog::warn("[DBManager] Attempt {} failed: {}", attempt, e.what());
            if (this->dbManager) {
                delete this->dbManager;
                this->dbManager = nullptr;
            }
        } catch (...) {
            spdlog::warn("[DBManager] Attempt {} failed with unknown exception", attempt);
            if (this->dbManager) {
                delete this->dbManager;
                this->dbManager = nullptr;
            }
        }
        
        if (attempt < 5) {
            // Qt-safe delay between attempts - use QEventLoop instead of sleep
            QEventLoop loop;
            QTimer::singleShot(100, &loop, &QEventLoop::quit);
            loop.exec();
        }
    }
    
    if (!this->dbManager) {
        spdlog::error("[DBManager] All 5 initialization attempts failed - proceeding with null DBManager");
        spdlog::error("[DBManager] Qt SQL subsystem may be compromised - expect potential UI issues");
    }
}

void HavocSpace::Havoc::Init( int argc, char** argv )
{
    auto List      = std::vector<Util::ConnectionInfo>();
    auto Connect   = new HavocNamespace::UserInterface::Dialogs::Connect;
    auto Arguments = cmdline::parser();
    auto Path      = std::string();

    Arguments.add( "debug",  '\0', "debug mode" );
    Arguments.add( "config", '\0', "toml config path" );
    Arguments.parse_check( argc, argv );


    if ( Arguments.exist( "debug" ) ) {
        spdlog::set_level( spdlog::level::debug );
        spdlog::debug( "Debug mode enabled" );
    }

    if ( Arguments.exist( "config" ) ) {
        Path = Arguments.get<std::string>( "config" );

        if ( ! QFile::exists( Path.c_str() ) ) {
            Path = std::string();
        }
    }

    if ( Path.empty() ) {
        Path = "client/config.toml";
    }

    if ( ! QFile::exists( Path.c_str() ) ) {
        Path = "config.toml";

        if ( ! QFile::exists( Path.c_str() ) ) {
            spdlog::error( "couldn't find config file" );
            Exit();
        }
    }

    Config = toml::parse( Path );
    spdlog::info( "loaded config file: {}", Path );

    /* TODO: handle any kind of error */
    const auto& font   = toml::find( Config, "font" );
    const auto  family = toml::find<std::string>( font, "family" );
    const auto  size   = toml::find<int>( font, "size" );

    QTextCodec::setCodecForLocale( QTextCodec::codecForName( "UTF-8" ) );
    QApplication::setFont( QFont( family.c_str(), size ) );
        QTimer::singleShot( 10, [&]() {
        QApplication::setFont( QFont( family.c_str(), size ) );
    } );

    this->HavocMainWindow->setVisible( false );

    Connect->TeamserverList = dbManager->listTeamservers();
    Connect->passDB( this->dbManager );
    Connect->setupUi( new QDialog );

    HavocX::Teamserver = Connect->StartDialog( false );

    delete Connect;
}

void HavocSpace::Havoc::Start()
{
    this->ClientInitConnect = false;
    this->HavocMainWindow->setVisible( true );
    this->HavocMainWindow->setCentralWidget( this->HavocAppUI.centralwidget );
    this->HavocMainWindow->show();
}

void HavocSpace::Havoc::Exit()
{
    spdlog::critical( "Exit Program" );
    HavocApplication->HavocMainWindow->close();

    exit( 0 );
}

Havoc::~Havoc()
{
    delete this->dbManager;
    delete this->HavocMainWindow;
}
