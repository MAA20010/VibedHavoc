#include <global.hpp>
#include <spdlog/spdlog.h>

#include <UserInterface/Widgets/OnlineOperators.h>
#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <Havoc/Connector.hpp>
#include <Util/ColorText.h>

HavocNamespace::UserInterface::SmallWidgets::OnlineOperators::OnlineOperators()
{
    OnlineOperatorsWidget = nullptr;
    layoutMain = nullptr;
    operatorConsole = nullptr;
}

void HavocNamespace::UserInterface::SmallWidgets::OnlineOperators::setupUi( QWidget* widget )
{
    if ( widget->objectName().isEmpty() )
        widget->setObjectName( QString::fromUtf8( "OnlineOperatorsWidget" ) );

    OnlineOperatorsWidget = widget;

    // Main vertical layout
    layoutMain = new QVBoxLayout( OnlineOperatorsWidget );
    layoutMain->setContentsMargins( 0, 0, 0, 0 );
    layoutMain->setSpacing( 0 );

    // Create operator console (like EventViewer)
    operatorConsole = new QTextEdit( OnlineOperatorsWidget );
    operatorConsole->setObjectName( QString::fromUtf8( "operatorConsole" ) );
    operatorConsole->setReadOnly( true );
    
    layoutMain->addWidget( operatorConsole );

    // Setup styling
    setupStyling();
}

void HavocNamespace::UserInterface::SmallWidgets::OnlineOperators::setupStyling()
{
    auto consoleStyle = QString(
        "QTextEdit {"
        "    background-color: #282a36;"
        "    color: #f8f8f2;"
        "    border: 1px solid #44475a;"
        "    font-family: 'Consolas', 'Monaco', monospace;"
        "    font-size: 13px;"
        "    selection-background-color: #44475a;"
        "}"
        "QScrollBar:vertical {"
        "    background-color: #282a36;"
        "    width: 12px;"
        "    border: none;"
        "}"
        "QScrollBar::handle:vertical {"
        "    background-color: #44475a;"
        "    border-radius: 6px;"
        "    min-height: 20px;"
        "}"
        "QScrollBar::handle:vertical:hover {"
        "    background-color: #6272a4;"
        "}"
    );

    operatorConsole->setStyleSheet( consoleStyle );
}

void HavocNamespace::UserInterface::SmallWidgets::OnlineOperators::AppendText( const QString& Time, const QString& text )
{
    if ( !operatorConsole ) {
        return;
    }
    operatorConsole->append(text);
}

void HavocNamespace::UserInterface::SmallWidgets::OnlineOperators::updateOperatorDisplay()
{
    if ( !operatorConsole ) {
        return;
    }
    
    // Clear and rebuild the entire display with current operators
    operatorConsole->clear();
    
    for ( const QString& username : connectedOperators ) {
        QString operatorLine = "<span style='font-size: 14px;'>[" + Util::ColorText::Green( "+" ) + "] <span style='color: white;'>👤</span> " + Util::ColorText::Green( username + " online" ) + "</span>";
        operatorConsole->append( operatorLine );
    }
}

void HavocNamespace::UserInterface::SmallWidgets::OnlineOperators::updateTabTitle()
{
    // Access the teamserver tab session to update the tab title
    auto Teamserver = HavocX::Teamserver.TabSession;
    if ( !Teamserver || !Teamserver->tabWidgetSmall || !OnlineOperatorsWidget ) {
        return;
    }
    
    // Find the tab index for this widget
    for ( int i = 0; i < Teamserver->tabWidgetSmall->count(); i++ ) {
        if ( Teamserver->tabWidgetSmall->widget( i ) == OnlineOperatorsWidget ) {
            QString newTitle = QString( "Online Operators (👤 %1)" ).arg( connectedOperators.size() );
            Teamserver->tabWidgetSmall->setTabText( i, newTitle );
            break;
        }
    }
}

int HavocNamespace::UserInterface::SmallWidgets::OnlineOperators::getConnectedCount() const
{
    return connectedOperators.size();
}

void HavocNamespace::UserInterface::SmallWidgets::OnlineOperators::onUserConnected( QString username, QString timestamp )
{
    if ( !operatorConsole || !OnlineOperatorsWidget ) {
        return;
    }
    
    // Add to connected list if not already there
    if ( !connectedOperators.contains( username ) ) {
        connectedOperators.append( username );
    }
    
    // Refresh the persistent display
    updateOperatorDisplay();
    updateTabTitle();
}

void HavocNamespace::UserInterface::SmallWidgets::OnlineOperators::onUserDisconnected( QString username, QString timestamp )
{
    if ( !operatorConsole || !OnlineOperatorsWidget ) {
        return;
    }
    
    // Remove from connected list
    connectedOperators.removeAll( username );
    
    // Refresh the persistent display (user line will be gone)
    updateOperatorDisplay();
    updateTabTitle();
}
