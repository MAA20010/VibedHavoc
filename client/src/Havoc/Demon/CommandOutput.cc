#include <QJsonDocument>
#include <QJsonArray>
#include <QTime>

#include <Havoc/DemonCmdDispatch.h>
#include <Havoc/Packager.hpp>
#include <Havoc/Connector.hpp>

#include <UserInterface/Widgets/DemonInteracted.h>
#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <UserInterface/Widgets/ProcessList.hpp>

#include <Util/ColorText.h>
#include <QFile>

using namespace HavocNamespace::HavocSpace;

void DispatchOutput::MessageOutput( QString JsonString, const QString& Date = "" ) const
{
    auto JsonDocument = QJsonDocument::fromJson( QByteArray::fromBase64( JsonString.toLocal8Bit( ) ) );
    auto TaskID       = JsonDocument[ "TaskID" ].toString();
    auto MessageType  = JsonDocument[ "Type" ].toString();
    auto Message      = JsonDocument[ "Message" ].toString();
    auto Output       = JsonDocument[ "Output" ].toString();


    if ( Message.length() > 0 )
    {
        if ( MessageType == "Error" || MessageType == "Erro" )
            this->DemonCommandInstance->DemonConsole->TaskError( Message );
        else if ( MessageType == "Good" )
            this->DemonCommandInstance->DemonConsole->AppendRaw( Util::ColorText::Green( "[+]" ) + " " + Message );
        else if ( MessageType == "Info" )
            this->DemonCommandInstance->DemonConsole->AppendRaw( Util::ColorText::Cyan( "[*]" ) + " " + Message );
        else if ( MessageType == "Warning" || MessageType == "Warn" )
            this->DemonCommandInstance->DemonConsole->AppendRaw( Util::ColorText::Yellow( "[!]" ) + " " + Message );
        else
            this->DemonCommandInstance->DemonConsole->AppendRaw( Util::ColorText::Purple( "[^]" ) + " " + Message );
    }

    if ( ! Output.isEmpty() )
    {
        //printf("task: %s\n", TaskID.toUtf8().constData());
        if (HavocX::callbackMessage)
        {
            PyObject *arglist = Py_BuildValue( "s", Output.toUtf8().constData() );
            PyObject* result = PyObject_CallFunctionObjArgs( HavocX::callbackMessage, arglist, NULL );
            Py_XDECREF(result);
            Py_DECREF(arglist);
            Py_XDECREF( HavocX::callbackMessage );
            HavocX::callbackMessage = NULL;
        }
        // Escape HTML special characters to prevent malformed output from breaking the UI
        // This ensures usernames like <Admin> or User&Group display correctly as literal text
        this->DemonCommandInstance->DemonConsole->AppendRaw( Output.toHtmlEscaped() );
    }

    if ( JsonDocument[ "MiscType" ].toString().compare( "" ) != 0 )
    {
        auto Type = JsonDocument[ "MiscType" ].toString();
        auto Data = JsonDocument[ "MiscData" ].toString();

        if ( Type.compare( "screenshot" ) == 0 )
        {
            auto DecodedData = QByteArray::fromBase64( Data.toLocal8Bit() );
            auto MetadataJSON = JsonDocument[ "MiscData2" ].toString();
            
            // Parse enhanced metadata JSON
            auto MetadataDoc = QJsonDocument::fromJson( MetadataJSON.toUtf8() );
            if ( !MetadataDoc.isEmpty() && MetadataDoc.isObject() ) {
                auto MetadataObj = MetadataDoc.object();
                auto Name = MetadataObj["filename"].toString();
                auto Operator = MetadataObj["operator"].toString();
                auto ExternalIP = MetadataObj["external_ip"].toString();
                auto Hostname = MetadataObj["hostname"].toString();
                auto SessionID = MetadataObj["session_id"].toString();
                
                // Add screenshot with enhanced metadata
                HavocX::Teamserver.TabSession->LootWidget->AddScreenshotWithMetadata( DemonCommandInstance->DemonID, Name, Date, DecodedData, Operator, ExternalIP, Hostname, SessionID );
            } else {
                // Fallback to old method if JSON parsing fails
                HavocX::Teamserver.TabSession->LootWidget->AddScreenshot( DemonCommandInstance->DemonID, MetadataJSON, Date, DecodedData );
            }
        }
        else if ( Type.compare( "download" ) == 0 )
        {
            auto MiscDataInfo = JsonDocument[ "MiscData2" ].toString().split( ";" );
            auto Name         = QByteArray::fromBase64( MiscDataInfo[ 0 ].toLocal8Bit() );
            auto Size         = ( MiscDataInfo[ 1 ] );

            HavocX::Teamserver.TabSession->LootWidget->AddDownload( DemonCommandInstance->DemonID, Name, Size, Date, nullptr );
            
            // Request loot sync from server to get enhanced metadata
            auto Package = Util::Packager::Package{
                .Head = {
                    .Event   = Util::Packager::Loot::Type,
                    .User    = HavocX::Teamserver.User.toStdString(),
                    .Time    = QTime::currentTime().toString( "hh:mm:ss" ).toStdString(),
                    .OneTime = "false",
                },
                .Body = {
                    .SubEvent = Util::Packager::Loot::ListAll,
                    .Info     = {},
                },
            };

            HavocX::Connector->SendPackage( &Package );
        }
        else if ( Type.compare( "ProcessUI" ) == 0 )
        {
            for ( auto& Session : HavocX::Teamserver.Sessions )
            {
                if ( Session.Name == DemonCommandInstance->DemonID )
                {
                    if ( Session.ProcessList )
                    {
                        auto Decoded = QByteArray::fromBase64( Data.toLocal8Bit() );
                        Session.ProcessList->UpdateProcessListJson( QJsonDocument::fromJson( Decoded ) );
                    }
                }
            }
        }
        else if ( Type.compare( "FileExplorer" ) == 0 )
        {
            for ( auto& Session : HavocX::Teamserver.Sessions )
            {
                if ( Session.Name == DemonCommandInstance->DemonID )
                {
                    if ( Session.FileBrowser )
                    {
                        auto Decoded = QByteArray::fromBase64( Data.toLocal8Bit() );
                        Session.FileBrowser->AddData( QJsonDocument::fromJson( Decoded ) );
                    }
                }
            }
        }
        else if ( Type.compare( "disconnect" ) == 0 )
        {
            HavocX::Teamserver.TabSession->SessionGraphWidget->GraphPivotNodeDisconnect( Data );
        }
        else if ( Type.compare( "reconnect" ) == 0 )
        {
            auto Split = Data.split( ";" );

            HavocX::Teamserver.TabSession->SessionGraphWidget->GraphPivotNodeReconnect( Split[ 0 ], Split[ 1 ] );
        }
    }
}
