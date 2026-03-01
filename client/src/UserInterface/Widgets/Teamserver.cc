#include <UserInterface/Widgets/Teamserver.hpp>

#include <QScrollBar>
#include <QDebug>

void Teamserver::setupUi( QWidget* Teamserver )
{
    TeamserverWidget = Teamserver;

    if ( Teamserver->objectName().isEmpty() )
        Teamserver->setObjectName( QString::fromUtf8( "Teamserver" ) );

    gridLayout = new QGridLayout( Teamserver );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );

    TeamserverLogger = new QTextEdit( /* PageLogger */ );
    TeamserverLogger->setObjectName( QString::fromUtf8( "TeamserverLogger" ) );
    TeamserverLogger->setReadOnly( true );

    gridLayout->addWidget( TeamserverLogger, 0, 0, 0, 0 );

    retranslateUi(  );

    QMetaObject::connectSlotsByName( TeamserverWidget );
}

void Teamserver::retranslateUi()
{
    TeamserverWidget->setWindowTitle( QCoreApplication::translate( "Teamserver", "Teamserver", nullptr ) );
}

void Teamserver::AddLoggerText( const QString& Text ) const
{
    // CRITICAL: Validate TeamserverLogger before Qt operations
    if ( TeamserverLogger == nullptr ) {
        // Don't use spdlog here as it might cause recursion
        qDebug() << "ERROR: TeamserverLogger is NULL in AddLoggerText";
        return;
    }
    
    TeamserverLogger->append( Text );
    TeamserverLogger->verticalScrollBar()->setValue( TeamserverLogger->verticalScrollBar()->maximum() );
}
