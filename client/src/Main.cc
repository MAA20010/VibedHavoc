#include <global.hpp>
#include <Havoc/Havoc.hpp>
#include <QTimer>
#include <csignal>
#include <QCoreApplication>

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        spdlog::info("Received signal {}, shutting down gracefully...", signal);
        QCoreApplication::quit();
    }
}

auto main(
    int    argc,
    char** argv
) -> int {
    auto HavocApp = QApplication( argc, argv );
    auto Status   = 0;

    // Setup signal handling for graceful shutdown
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    QGuiApplication::setWindowIcon( QIcon( ":/Havoc.ico" ) );

    HavocNamespace::HavocApplication = new HavocNamespace::HavocSpace::Havoc( new QMainWindow );
    HavocNamespace::HavocApplication->Init( argc, argv );

    Status = QApplication::exec();

    spdlog::info( "Havoc Application status: {}", Status );

    return Status;
}
