#include <global.hpp>

#include <UserInterface/Widgets/NetworkDiagram.hpp>
#include <Util/ColorText.h>

#include <QKeyEvent>
#include <QMouseEvent>
#include <QCloseEvent>
#include <QScrollBar>
#include <QGraphicsSceneContextMenuEvent>
#include <QMenu>
#include <QInputDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QDir>
#include <QCoreApplication>
#include <QLabel>
#include <cmath>

using namespace HavocNamespace::Util;

// ==================================================
// ============= NetworkDiagramWidget ===============
// ==================================================

NetworkDiagramWidget::NetworkDiagramWidget( QWidget* parent ) : QGraphicsView( parent )
{
    DiagramScene = new QGraphicsScene( this );
    DiagramScene->setItemIndexMethod( QGraphicsScene::BspTreeIndex );
    
    // Start with minimal scene - will grow dynamically
    DiagramScene->setSceneRect( -1000, -1000, 2000, 2000 );

    setScene( DiagramScene );
    setCacheMode( CacheBackground );
    setViewportUpdateMode( BoundingRectViewportUpdate );
    setRenderHint( QPainter::Antialiasing );
    setRenderHint( QPainter::SmoothPixmapTransform ); // High-quality image scaling
    setTransformationAnchor( AnchorUnderMouse );
    
    // Enable rubber band selection for multiple nodes
    setDragMode( QGraphicsView::RubberBandDrag );
    
    scaleView( qreal( 1 ) );
    
    // Initialize dynamic scene rect
    updateDynamicSceneRect();
}

NetworkDiagramWidget::~NetworkDiagramWidget()
{
    // Clean up nodes and edges
    for ( auto node : NodeList )
    {
        if ( node )
        {
            // Edges will be deleted by scene
            delete node;
        }
    }
    NodeList.clear();
}

void NetworkDiagramWidget::addNode( NetworkNodeType type, QString name, QString ip, QPointF position )
{
    // Validate inputs to prevent null bytes and issues
    if ( name.isEmpty() || name.contains( QChar( '\0' ) ) )
    {
        name = "NewNode";
    }
    
    if ( ip.isEmpty() || ip.contains( QChar( '\0' ) ) )
    {
        ip = "0.0.0.0";
    }
    
    auto node = new NetworkNode( type, name, ip, this );
    node->setPos( position );
    
    DiagramScene->addItem( node );
    NodeList.push_back( node );
    
    // Trigger auto-save
    emit dataChanged();
}

void NetworkDiagramWidget::removeNode( NetworkNode* node )
{
    if ( !node )
        return;
    
    // Remove all edges connected to this node
    auto edges = node->edges();
    for ( auto edge : edges )
    {
        DiagramScene->removeItem( edge );
        delete edge;
    }
    
    // Remove node from list
    auto it = std::find( NodeList.begin(), NodeList.end(), node );
    if ( it != NodeList.end() )
    {
        NodeList.erase( it );
    }
    
    // Remove from scene
    DiagramScene->removeItem( node );
    delete node;
    
    // Trigger auto-save
    emit dataChanged();
}

void NetworkDiagramWidget::editNode( NetworkNode* node, QString newName, QString newIP, NetworkNodeType newType )
{
    if ( !node )
        return;
    
    // Validate inputs
    if ( newName.contains( QChar( '\0' ) ) )
    {
        return;
    }
    
    if ( newIP.contains( QChar( '\0' ) ) )
    {
        return;
    }
    
    node->setName( newName );
    node->setIP( newIP );
    node->setType( newType );
    node->update();
    
    // Trigger auto-save
    emit dataChanged();
}

void NetworkDiagramWidget::addConnection( NetworkNode* source, NetworkNode* dest )
{
    if ( !source || !dest || source == dest )
        return;
    
    // Check if connection already exists
    auto edges = source->edges();
    for ( auto edge : edges )
    {
        if ( ( edge->source == source && edge->dest == dest ) ||
             ( edge->source == dest && edge->dest == source ) )
        {
            return; // Connection already exists
        }
    }
    
    auto edge = new NetworkEdge( source, dest );
    DiagramScene->addItem( edge );
    
    // Trigger auto-save
    emit dataChanged();
}

void NetworkDiagramWidget::removeConnection( NetworkEdge* edge )
{
    if ( !edge )
        return;
    
    // Remove edge from nodes
    if ( edge->source )
        edge->source->removeEdge( edge );
    
    if ( edge->dest )
        edge->dest->removeEdge( edge );
    
    // Remove from scene
    DiagramScene->removeItem( edge );
    delete edge;
    
    // Trigger auto-save
    emit dataChanged();
}

void NetworkDiagramWidget::reverseEdgeDirection( NetworkEdge* edge )
{
    if ( !edge )
        return;
    
    edge->reverse();
    edge->adjust();
    edge->update();
}

void NetworkDiagramWidget::keyPressEvent( QKeyEvent* event )
{
    switch ( event->key() )
    {
        case Qt::Key_Plus:
            zoomIn();
            break;

        case Qt::Key_Minus:
            zoomOut();
            break;

        default:
            QGraphicsView::keyPressEvent( event );
    }
}

void NetworkDiagramWidget::resizeEvent( QResizeEvent* event )
{
    // Update scene rect dynamically
    updateDynamicSceneRect();
    
    QGraphicsView::resizeEvent( event );
}

void NetworkDiagramWidget::wheelEvent( QWheelEvent* event )
{
    scaleView( pow( 2., event->angleDelta().y() / 500.0 ) );
}

void NetworkDiagramWidget::mousePressEvent( QMouseEvent* event )
{
    if ( event->button() == Qt::MiddleButton )
    {
        // Start panning with middle mouse button
        isPanning = true;
        lastPanPoint = event->pos();
        setDragMode( QGraphicsView::NoDrag );
        setCursor( Qt::ClosedHandCursor );
        event->accept();
        return;
    }
    
    // Let the base class handle rubber band selection and node interaction
    QGraphicsView::mousePressEvent( event );
}

void NetworkDiagramWidget::mouseMoveEvent( QMouseEvent* event )
{
    if ( isPanning && ( event->buttons() & Qt::MiddleButton ) )
    {
        // Calculate pan delta
        QPoint delta = event->pos() - lastPanPoint;
        lastPanPoint = event->pos();
        
        // Pan the view by adjusting scrollbars
        horizontalScrollBar()->setValue( horizontalScrollBar()->value() - delta.x() );
        verticalScrollBar()->setValue( verticalScrollBar()->value() - delta.y() );
        
        event->accept();
        return;
    }
    
    // Let the base class handle node dragging
    QGraphicsView::mouseMoveEvent( event );
}

void NetworkDiagramWidget::mouseReleaseEvent( QMouseEvent* event )
{
    if ( event->button() == Qt::MiddleButton && isPanning )
    {
        // Stop panning, restore rubber band drag
        isPanning = false;
        setDragMode( QGraphicsView::RubberBandDrag );
        setCursor( Qt::ArrowCursor );
        event->accept();
        return;
    }
    
    // Let the base class handle node interaction
    QGraphicsView::mouseReleaseEvent( event );
}

void NetworkDiagramWidget::contextMenuEvent( QContextMenuEvent* event )
{
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
    
    // Check if we clicked on empty space
    QGraphicsItem* item = itemAt( event->pos() );
    if ( !item )
    {
        // Context menu for empty space
        QMenu menu;
        menu.setStyleSheet( MenuStyle );
        
        auto addNodeMenu = new QMenu( "Add Node" );
        addNodeMenu->setStyleSheet( MenuStyle );
        
        addNodeMenu->addAction( "Windows 11" );
        addNodeMenu->addAction( "Windows 10" );
        addNodeMenu->addAction( "Windows 7" );
        addNodeMenu->addAction( "Windows XP" );
        addNodeMenu->addAction( "Linux" );
        addNodeMenu->addAction( "MacOS" );
        addNodeMenu->addAction( "Server" );
        
        menu.addMenu( addNodeMenu );
        menu.addAction( "Clear All Nodes" );
        
        auto action = menu.exec( event->globalPos() );
        
        if ( action )
        {
            if ( action->text() == "Windows 11" || action->text() == "Windows 10" || 
                 action->text() == "Windows 7" || action->text() == "Windows XP" ||
                 action->text() == "Linux" || action->text() == "MacOS" || action->text() == "Server" )
            {
                // Prompt for node details
                bool ok;
                QString name = QInputDialog::getText( this, "Node Name", "Enter node name:", 
                                                     QLineEdit::Normal, "NewNode", &ok );
                
                if ( ok && !name.isEmpty() )
                {
                    QString ip = QInputDialog::getText( this, "Node IP", "Enter IP address:", 
                                                       QLineEdit::Normal, "192.168.1.1", &ok );
                    
                    if ( ok && !ip.isEmpty() )
                    {
                        NetworkNodeType type = NetworkNodeType::Windows10;
                        if ( action->text() == "Windows 11" ) type = NetworkNodeType::Windows11;
                        else if ( action->text() == "Windows 10" ) type = NetworkNodeType::Windows10;
                        else if ( action->text() == "Windows 7" ) type = NetworkNodeType::Windows7;
                        else if ( action->text() == "Windows XP" ) type = NetworkNodeType::WindowsXP;
                        else if ( action->text() == "Linux" ) type = NetworkNodeType::Linux;
                        else if ( action->text() == "MacOS" ) type = NetworkNodeType::MacOS;
                        else if ( action->text() == "Server" ) type = NetworkNodeType::Server;
                        
                        // Add node at cursor position (map to scene coordinates)
                        QPointF scenePos = mapToScene( event->pos() );
                        addNode( type, name, ip, scenePos );
                    }
                }
            }
            else if ( action->text() == "Clear All Nodes" )
            {
                auto reply = QMessageBox::question( this, "Clear All", 
                                                    "Are you sure you want to delete all nodes?",
                                                    QMessageBox::Yes | QMessageBox::No );
                
                if ( reply == QMessageBox::Yes )
                {
                    // Delete all nodes (copy list first to avoid iterator issues)
                    auto nodesCopy = NodeList;
                    for ( auto node : nodesCopy )
                    {
                        removeNode( node );
                    }
                }
            }
        }
        
        delete addNodeMenu;
    }
    else
    {
        // Let nodes handle their own context menu
        QGraphicsView::contextMenuEvent( event );
    }
}

void NetworkDiagramWidget::drawBackground( QPainter* painter, const QRectF& rect )
{
    Q_UNUSED( rect );

    auto sceneRect  = this->sceneRect();
    auto gradient   = QLinearGradient( sceneRect.topLeft(), sceneRect.bottomRight() );
    auto Background = HavocNamespace::Util::ColorText::Colors::Hex::Background;

    gradient.setColorAt( 0, QColor( Background ) );

    painter->fillRect( rect.intersected( sceneRect ), gradient );
    painter->setBrush( Qt::NoBrush );
    painter->drawRect( sceneRect );
}

void NetworkDiagramWidget::scaleView( qreal scaleFactor )
{
    qreal factor = transform().scale( scaleFactor, scaleFactor ).mapRect( QRectF( 0, 0, 1, 1 ) ).width();
    
    // Zoom limits
    if ( factor < 0.05 || factor > 50 )
        return;

    scale( scaleFactor, scaleFactor );
    
    // Update scene rect based on new zoom level
    updateDynamicSceneRect();
}

void NetworkDiagramWidget::updateDynamicSceneRect()
{
    // Get current zoom level
    qreal currentScale = transform().m11(); // m11 is the horizontal scale factor
    
    // Calculate dynamic scene size based on zoom level
    // More zoomed out = larger scene area needed
    qreal baseSize = 5000;
    qreal dynamicSize = baseSize / currentScale;
    
    // Ensure minimum size for usability
    dynamicSize = qMax( dynamicSize, qreal( 2000 ) );
    
    // Get all node positions to ensure they're included
    QRectF itemsBounds;
    const auto items = DiagramScene->items();
    for ( QGraphicsItem* item : items )
    {
        if ( qgraphicsitem_cast<NetworkNode*>( item ) )
        {
            itemsBounds = itemsBounds.united( item->sceneBoundingRect() );
        }
    }
    
    // Expand bounds to include padding around nodes
    qreal padding = dynamicSize * 0.3;
    itemsBounds.adjust( -padding, -padding, padding, padding );
    
    // Set scene rect to encompass both dynamic size and actual content
    QRectF newSceneRect = QRectF( -dynamicSize/2, -dynamicSize/2, dynamicSize, dynamicSize );
    newSceneRect = newSceneRect.united( itemsBounds );
    
    DiagramScene->setSceneRect( newSceneRect );
}

void NetworkDiagramWidget::zoomIn()
{
    scaleView( qreal( 1.2 ) );
}

void NetworkDiagramWidget::zoomOut()
{
    scaleView( 1 / qreal( 1.2 ) );
}

void NetworkDiagramWidget::clearAll()
{
    // Delete all nodes (which will also delete their edges)
    auto nodesCopy = NodeList;
    for ( auto node : nodesCopy )
    {
        removeNode( node );
    }
}

void NetworkDiagramWidget::saveToFile( const QString& filename )
{
    QJsonObject root;
    root["profile_name"] = ProfileName;
    root["version"] = "1.0";
    
    // Save nodes
    QJsonArray nodesArray;
    for ( auto node : NodeList )
    {
        QJsonObject nodeObj;
        nodeObj["name"] = node->getName();
        nodeObj["ip"] = node->getIP();
        nodeObj["type"] = static_cast<int>( node->getType() );
        nodeObj["compromised"] = node->isCompromised();
        nodeObj["high_privilege"] = node->isHighPrivilege();
        nodeObj["x"] = node->pos().x();
        nodeObj["y"] = node->pos().y();
        nodesArray.append( nodeObj );
    }
    root["nodes"] = nodesArray;
    
    // Save connections
    QJsonArray connectionsArray;
    QSet<NetworkEdge*> savedEdges;
    
    for ( auto node : NodeList )
    {
        auto edges = node->edges();
        for ( auto edge : edges )
        {
            if ( savedEdges.contains( edge ) )
                continue;
            
            savedEdges.insert( edge );
            
            QJsonObject connObj;
            // Find indices
            int sourceIdx = -1, destIdx = -1;
            for ( size_t i = 0; i < NodeList.size(); i++ )
            {
                if ( NodeList[i] == edge->source ) sourceIdx = i;
                if ( NodeList[i] == edge->dest ) destIdx = i;
            }
            
            if ( sourceIdx != -1 && destIdx != -1 )
            {
                connObj["source"] = sourceIdx;
                connObj["dest"] = destIdx;
                connectionsArray.append( connObj );
            }
        }
    }
    root["connections"] = connectionsArray;
    
    // Write to file
    QJsonDocument doc( root );
    QFile file( filename );
    if ( file.open( QIODevice::WriteOnly ) )
    {
        file.write( doc.toJson() );
        file.close();
    }
}

void NetworkDiagramWidget::loadFromFile( const QString& filename )
{
    QFile file( filename );
    if ( !file.open( QIODevice::ReadOnly ) )
        return;
    
    QByteArray data = file.readAll();
    file.close();
    
    QJsonDocument doc = QJsonDocument::fromJson( data );
    if ( doc.isNull() || !doc.isObject() )
        return;
    
    QJsonObject root = doc.object();
    
    // Clear existing diagram
    clearAll();
    
    // Load profile name
    if ( root.contains( "profile_name" ) )
        ProfileName = root["profile_name"].toString();
    
    // Load nodes
    if ( root.contains( "nodes" ) )
    {
        QJsonArray nodesArray = root["nodes"].toArray();
        for ( const auto& nodeVal : nodesArray )
        {
            QJsonObject nodeObj = nodeVal.toObject();
            
            QString name = nodeObj["name"].toString();
            QString ip = nodeObj["ip"].toString();
            NetworkNodeType type = static_cast<NetworkNodeType>( nodeObj["type"].toInt() );
            bool compromised = nodeObj["compromised"].toBool( false );
            bool highPrivilege = nodeObj["high_privilege"].toBool( false );
            qreal x = nodeObj["x"].toDouble();
            qreal y = nodeObj["y"].toDouble();
            
            addNode( type, name, ip, QPointF( x, y ) );
            
            // Set status after adding
            if ( !NodeList.empty() )
            {
                if ( compromised )
                    NodeList.back()->setCompromised( true );
                if ( highPrivilege )
                    NodeList.back()->setHighPrivilege( true );
            }
        }
    }
    
    // Load connections
    if ( root.contains( "connections" ) )
    {
        QJsonArray connectionsArray = root["connections"].toArray();
        for ( const auto& connVal : connectionsArray )
        {
            QJsonObject connObj = connVal.toObject();
            
            int sourceIdx = connObj["source"].toInt();
            int destIdx = connObj["dest"].toInt();
            
            if ( sourceIdx >= 0 && sourceIdx < static_cast<int>( NodeList.size() ) &&
                 destIdx >= 0 && destIdx < static_cast<int>( NodeList.size() ) )
            {
                addConnection( NodeList[sourceIdx], NodeList[destIdx] );
            }
        }
    }
}

// ==================================================
// ================ NetworkNode =====================
// ==================================================

NetworkNode::NetworkNode( NetworkNodeType type, QString name, QString ip, NetworkDiagramWidget* diagramWidget )
    : diagram( diagramWidget )
{
    this->NodeType = type;
    this->NodeName = name;
    this->NodeIP = ip;
    
    this->NodePainterSize = QRectF( -60, -80, 120, 160 );

    setFlag( ItemIsMovable );
    setFlag( ItemSendsGeometryChanges );
    setFlag( ItemIsSelectable );
    setAcceptHoverEvents( true );
    setCacheMode( DeviceCoordinateCache );
    setZValue( 1 );
}

void NetworkNode::setName( const QString& name )
{
    NodeName = name;
}

void NetworkNode::setIP( const QString& ip )
{
    NodeIP = ip;
}

void NetworkNode::setType( NetworkNodeType type )
{
    NodeType = type;
}

void NetworkNode::setCompromised( bool compromised )
{
    IsCompromised = compromised;
}

void NetworkNode::setHighPrivilege( bool highPriv )
{
    IsHighPrivilege = highPriv;
}

void NetworkNode::addEdge( NetworkEdge* edge )
{
    if ( !edge )
        return;
    
    edgeList << edge;
    edge->adjust();
}

void NetworkNode::removeEdge( NetworkEdge* edge )
{
    edgeList.removeAll( edge );
}

QVector<NetworkEdge*> NetworkNode::edges() const
{
    return edgeList;
}

QRectF NetworkNode::boundingRect() const
{
    return NodePainterSize;
}

QPainterPath NetworkNode::shape() const
{
    auto path = QPainterPath();
    path.addRect( NodePainterSize );
    return path;
}

void NetworkNode::paint( QPainter* painter, const QStyleOptionGraphicsItem* option, QWidget* )
{
    Q_UNUSED( option );
    
    // Enable smooth image scaling for this painter
    painter->setRenderHint( QPainter::Antialiasing );
    painter->setRenderHint( QPainter::SmoothPixmapTransform );
    
    // Determine image based on node type and privilege level
    QString imagePath;
    switch ( NodeType )
    {
        case NetworkNodeType::Windows11:
            imagePath = IsHighPrivilege ? ":/images/win11-high" : ":/images/win11";
            break;
        case NetworkNodeType::Windows10:
            imagePath = IsHighPrivilege ? ":/images/win10-8-high" : ":/images/win10-8";
            break;
        case NetworkNodeType::Windows7:
            imagePath = IsHighPrivilege ? ":/images/win7-vista-high" : ":/images/win7-vista";
            break;
        case NetworkNodeType::WindowsXP:
            imagePath = IsHighPrivilege ? ":/images/winxp-high" : ":/images/winxp";
            break;
        case NetworkNodeType::Linux:
            imagePath = IsHighPrivilege ? ":/images/linux-high" : ":/images/linux";
            break;
        case NetworkNodeType::MacOS:
            imagePath = IsHighPrivilege ? ":/images/macos-high" : ":/images/macos";
            break;
        case NetworkNodeType::Server:
            imagePath = ":/images/SessionHavoc"; // Server doesn't have -high variant
            break;
        default:
            imagePath = IsHighPrivilege ? ":/images/unknown-high" : ":/images/unknown";
            break;
    }
    
    auto image = QImage( imagePath );
    
    // Draw the image (centered)
    painter->drawImage( QRectF( -40, -40, 80, 80 ), image );
    
    // Draw Owned.png overlay if compromised
    if ( IsCompromised )
    {
        auto ownedIcon = QImage( ":/images/Owned" );
        if ( !ownedIcon.isNull() )
        {
            // Draw in top-right corner (50% bigger = 30x30)
            painter->drawImage( QRectF( 20, -50, 30, 30 ), ownedIcon );
        }
    }
    
    // Draw selection highlight if selected
    if ( isSelected() )
    {
        painter->setPen( QPen( QColor( 0x8be9fd ), 2, Qt::DashLine ) ); // Cyan
        painter->drawRect( QRectF( -45, -45, 90, 90 ) );
    }
    
    // Draw node name (above image)
    painter->setPen( QPen( Qt::white ) );
    QFont font = painter->font();
    font.setBold( true );
    font.setPointSize( 10 );
    painter->setFont( font );
    painter->drawText( QRectF( -60, -70, 120, 20 ), Qt::AlignCenter, NodeName );
    
    // Draw IP address (below image)
    font.setBold( false );
    font.setPointSize( 9 );
    painter->setFont( font );
    painter->setPen( QPen( QColor( 0x8be9fd ) ) ); // Cyan
    painter->drawText( QRectF( -60, 50, 120, 20 ), Qt::AlignCenter, NodeIP );
}

QVariant NetworkNode::itemChange( GraphicsItemChange change, const QVariant& value )
{
    switch ( change )
    {
        case ItemPositionHasChanged:
        {
            // Update all connected edges
            for ( NetworkEdge* edge : qAsConst( edgeList ) )
            {
                edge->adjust();
            }
            break;
        }
        default:
            break;
    }

    return QGraphicsItem::itemChange( change, value );
}

void NetworkNode::mousePressEvent( QGraphicsSceneMouseEvent* event )
{
    update();
    QGraphicsItem::mousePressEvent( event );
}

void NetworkNode::mouseReleaseEvent( QGraphicsSceneMouseEvent* event )
{
    update();
    QGraphicsItem::mouseReleaseEvent( event );
}

void NetworkNode::mouseMoveEvent( QGraphicsSceneMouseEvent* event )
{
    QGraphicsItem::mouseMoveEvent( event );
}

void NetworkNode::contextMenuEvent( QGraphicsSceneContextMenuEvent* event )
{
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
    
    QMenu menu;
    menu.setStyleSheet( MenuStyle );
    
    menu.addAction( "Edit Node" );
    
    auto changeTypeMenu = new QMenu( "Change Type" );
    changeTypeMenu->setStyleSheet( MenuStyle );
    changeTypeMenu->addAction( "Windows 11" );
    changeTypeMenu->addAction( "Windows 10" );
    changeTypeMenu->addAction( "Windows 7" );
    changeTypeMenu->addAction( "Windows XP" );
    changeTypeMenu->addAction( "Linux" );
    changeTypeMenu->addAction( "MacOS" );
    changeTypeMenu->addAction( "Server" );
    
    menu.addMenu( changeTypeMenu );
    menu.addSeparator();
    
    // Compromised status toggle
    if ( IsCompromised )
        menu.addAction( "Mark as Clean" );
    else
        menu.addAction( "Mark as Compromised" );
    
    // Privilege level toggle
    if ( IsHighPrivilege )
        menu.addAction( "Mark as Normal User" );
    else
        menu.addAction( "Mark as High Privilege" );
    
    menu.addSeparator();
    menu.addAction( "Add Connection" );
    menu.addAction( "Remove All Connections" );
    menu.addSeparator();
    menu.addAction( "Delete Node" );
    
    auto action = menu.exec( event->screenPos() );
    
    if ( action )
    {
        if ( action->text() == "Edit Node" )
        {
            bool ok;
            QString newName = QInputDialog::getText( diagram, "Edit Node", "Node name:", 
                                                    QLineEdit::Normal, NodeName, &ok );
            
            if ( ok )
            {
                QString newIP = QInputDialog::getText( diagram, "Edit Node", "IP address:", 
                                                      QLineEdit::Normal, NodeIP, &ok );
                
                if ( ok )
                {
                    diagram->editNode( this, newName, newIP, NodeType );
                }
            }
        }
        else if ( action->text() == "Windows 11" || action->text() == "Windows 10" || 
                  action->text() == "Windows 7" || action->text() == "Windows XP" ||
                  action->text() == "Linux" || action->text() == "MacOS" || action->text() == "Server" )
        {
            NetworkNodeType newType = NetworkNodeType::Windows10;
            if ( action->text() == "Windows 11" ) newType = NetworkNodeType::Windows11;
            else if ( action->text() == "Windows 10" ) newType = NetworkNodeType::Windows10;
            else if ( action->text() == "Windows 7" ) newType = NetworkNodeType::Windows7;
            else if ( action->text() == "Windows XP" ) newType = NetworkNodeType::WindowsXP;
            else if ( action->text() == "Linux" ) newType = NetworkNodeType::Linux;
            else if ( action->text() == "MacOS" ) newType = NetworkNodeType::MacOS;
            else if ( action->text() == "Server" ) newType = NetworkNodeType::Server;
            
            diagram->editNode( this, NodeName, NodeIP, newType );
        }
        else if ( action->text() == "Mark as Compromised" )
        {
            setCompromised( true );
            update();
            diagram->dataChanged(); // Trigger save
        }
        else if ( action->text() == "Mark as Clean" )
        {
            setCompromised( false );
            update();
            diagram->dataChanged(); // Trigger save
        }
        else if ( action->text() == "Mark as High Privilege" )
        {
            setHighPrivilege( true );
            update();
            diagram->dataChanged(); // Trigger save
        }
        else if ( action->text() == "Mark as Normal User" )
        {
            setHighPrivilege( false );
            update();
            diagram->dataChanged(); // Trigger save
        }
        else if ( action->text() == "Add Connection" )
        {
            // Show list of other nodes to connect to
            QStringList nodeNames;
            QMap<QString, NetworkNode*> nodeMap;
            
            for ( auto node : diagram->getNodes() )
            {
                if ( node != this )
                {
                    QString displayName = node->getName() + " (" + node->getIP() + ")";
                    nodeNames << displayName;
                    nodeMap[displayName] = node;
                }
            }
            
            if ( nodeNames.isEmpty() )
            {
                QMessageBox::information( diagram, "No Nodes", "No other nodes available to connect to." );
            }
            else
            {
                bool ok;
                QString selected = QInputDialog::getItem( diagram, "Add Connection", 
                                                         "Select node to connect:", 
                                                         nodeNames, 0, false, &ok );
                
                if ( ok && !selected.isEmpty() )
                {
                    NetworkNode* targetNode = nodeMap[selected];
                    if ( targetNode )
                    {
                        diagram->addConnection( this, targetNode );
                    }
                }
            }
        }
        else if ( action->text() == "Remove All Connections" )
        {
            // Remove all edges connected to this node
            auto edgesCopy = edgeList;
            for ( auto edge : edgesCopy )
            {
                diagram->removeConnection( edge );
            }
        }
        else if ( action->text() == "Delete Node" )
        {
            diagram->removeNode( this );
            return; // Node is deleted, don't continue
        }
    }
    
    delete changeTypeMenu;
}

// ==================================================
// ================ NetworkEdge =====================
// ==================================================

NetworkEdge::NetworkEdge( NetworkNode* sourceNode, NetworkNode* destNode )
    : source( sourceNode ), dest( destNode )
{
    setAcceptedMouseButtons( Qt::RightButton );
    setAcceptHoverEvents( true );
    setZValue( 0 );

    if ( source )
        source->addEdge( this );
    
    if ( dest )
        dest->addEdge( this );

    adjust();
}

NetworkNode* NetworkEdge::sourceNode() const
{
    return source;
}

NetworkNode* NetworkEdge::destNode() const
{
    return dest;
}

void NetworkEdge::adjust()
{
    if ( !source || !dest )
        return;

    auto line = QLineF( mapFromItem( source, 0, 0 ), mapFromItem( dest, 0, 0 ) );
    auto length = line.length();

    prepareGeometryChange();

    if ( length > qreal( 20. ) )
    {
        // Increase edge space to clear text labels (IP below, name above)
        // Node bounds: -80 to +80 vertically, so need ~95px offset
        auto edgeSpace = 95;
        auto edgeOffset = QPointF( ( line.dx() * edgeSpace ) / length, ( line.dy() * edgeSpace ) / length );

        sourcePoint = line.p1() + edgeOffset;
        destPoint = line.p2() - edgeOffset;
    }
    else
    {
        sourcePoint = destPoint = line.p1();
    }
}

QRectF NetworkEdge::boundingRect() const
{
    if ( !source || !dest )
        return QRectF();

    qreal penWidth = 2;
    qreal extra = ( penWidth + arrowSize ) / 2.0;

    return QRectF( sourcePoint, QSizeF( destPoint.x() - sourcePoint.x(), 
                                        destPoint.y() - sourcePoint.y() ) )
            .normalized()
            .adjusted( -extra, -extra, extra, extra );
}

void NetworkEdge::reverse()
{
    // Swap source and dest
    auto temp = source;
    source = dest;
    dest = temp;
}

void NetworkEdge::contextMenuEvent( QGraphicsSceneContextMenuEvent* event )
{
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
    
    QMenu menu;
    menu.setStyleSheet( MenuStyle );
    
    menu.addAction( "Reverse Direction" );
    menu.addAction( "Delete Connection" );
    
    auto action = menu.exec( event->screenPos() );
    
    if ( action )
    {
        if ( action->text() == "Reverse Direction" )
        {
            reverse();
            adjust();
            update();
        }
        else if ( action->text() == "Delete Connection" )
        {
            // Find the diagram widget
            if ( scene() )
            {
                // Remove edge from both nodes
                if ( source )
                    source->removeEdge( this );
                if ( dest )
                    dest->removeEdge( this );
                
                // Remove from scene
                scene()->removeItem( this );
                delete this;
                return;
            }
        }
    }
}

void NetworkEdge::paint( QPainter* painter, const QStyleOptionGraphicsItem*, QWidget* )
{
    if ( !source || !dest )
        return;

    auto line = QLineF( sourcePoint, destPoint );
    if ( qFuzzyCompare( line.length(), qreal( 0. ) ) )
        return;

    // Draw the line
    painter->setPen( QPen( color, 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin ) );
    painter->drawLine( line );
    
    // Draw arrow pointing from source to dest
    auto angle = std::atan2( -line.dy(), line.dx() );
    
    QPointF arrowP1 = destPoint + QPointF( sin( angle - M_PI / 3 ) * arrowSize, 
                                            cos( angle - M_PI / 3 ) * arrowSize );
    QPointF arrowP2 = destPoint + QPointF( sin( angle - M_PI + M_PI / 3 ) * arrowSize, 
                                            cos( angle - M_PI + M_PI / 3 ) * arrowSize );
    
    painter->setBrush( color );
    painter->drawPolygon( QPolygonF() << destPoint << arrowP1 << arrowP2 );
}

// ==================================================
// ============ NetworkDiagramSidebar ===============
// ==================================================

NetworkDiagramSidebar::NetworkDiagramSidebar( QWidget* parent ) : QWidget( parent )
{
    MainLayout = new QVBoxLayout( this );
    MainLayout->setContentsMargins( 5, 5, 5, 5 );
    MainLayout->setSpacing( 5 );
    
    // Title label
    QLabel* titleLabel = new QLabel( "Node Types", this );
    titleLabel->setStyleSheet( "color: #f8f8f2; font-weight: bold; font-size: 11pt; padding: 5px;" );
    MainLayout->addWidget( titleLabel );
    
    // Scroll area for node buttons
    ScrollArea = new QScrollArea( this );
    ScrollArea->setWidgetResizable( true );
    ScrollArea->setHorizontalScrollBarPolicy( Qt::ScrollBarAlwaysOff );
    ScrollArea->setStyleSheet( 
        "QScrollArea { background-color: #282a36; border: none; }"
        "QScrollBar:vertical { background: #44475a; width: 10px; }"
        "QScrollBar::handle:vertical { background: #6272a4; border-radius: 5px; }"
    );
    
    ContentWidget = new QWidget();
    ContentLayout = new QVBoxLayout( ContentWidget );
    ContentLayout->setContentsMargins( 0, 0, 0, 0 );
    ContentLayout->setSpacing( 8 );
    
    setupNodeButtons();
    
    ContentLayout->addStretch();
    ScrollArea->setWidget( ContentWidget );
    MainLayout->addWidget( ScrollArea );
    
    setMinimumWidth( 120 );
    setMaximumWidth( 180 );
}

void NetworkDiagramSidebar::setupNodeButtons()
{
    auto buttonStyle = QString(
        "QPushButton {"
        "    background-color: #44475a;"
        "    color: #f8f8f2;"
        "    border: 1px solid #6272a4;"
        "    border-radius: 5px;"
        "    padding: 8px;"
        "    text-align: left;"
        "    font-size: 10pt;"
        "}"
        "QPushButton:hover {"
        "    background-color: #6272a4;"
        "    border: 1px solid #8be9fd;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #bd93f9;"
        "}"
    );
    
    struct NodeTypeInfo {
        NetworkNodeType type;
        QString label;
    };
    
    QVector<NodeTypeInfo> nodeTypes = {
        { NetworkNodeType::Windows11, "Windows 11" },
        { NetworkNodeType::Windows10, "Windows 10" },
        { NetworkNodeType::Windows7, "Windows 7" },
        { NetworkNodeType::WindowsXP, "Windows XP" },
        { NetworkNodeType::Linux, "Linux" },
        { NetworkNodeType::MacOS, "MacOS" },
        { NetworkNodeType::Server, "Server" }
    };
    
    for ( const auto& nodeInfo : nodeTypes )
    {
        QPushButton* btn = new QPushButton( ContentWidget );
        btn->setStyleSheet( buttonStyle );
        btn->setMinimumHeight( 40 );
        
        // Set icon
        QPixmap icon = getNodeIcon( nodeInfo.type );
        if ( !icon.isNull() )
        {
            btn->setIcon( QIcon( icon ) );
            btn->setIconSize( QSize( 24, 24 ) );
        }
        
        btn->setText( nodeInfo.label );
        
        connect( btn, &QPushButton::clicked, this, [this, nodeInfo]() {
            emit nodeTypeSelected( nodeInfo.type );
        });
        
        ContentLayout->addWidget( btn );
    }
}

QPixmap NetworkDiagramSidebar::getNodeIcon( NetworkNodeType type )
{
    QString imagePath;
    switch ( type )
    {
        case NetworkNodeType::Windows11:
            imagePath = ":/images/win11";
            break;
        case NetworkNodeType::Windows10:
            imagePath = ":/images/win10-8";
            break;
        case NetworkNodeType::Windows7:
            imagePath = ":/images/win7-vista";
            break;
        case NetworkNodeType::WindowsXP:
            imagePath = ":/images/winxp";
            break;
        case NetworkNodeType::Linux:
            imagePath = ":/images/linux";
            break;
        case NetworkNodeType::MacOS:
            imagePath = ":/images/macos";
            break;
        case NetworkNodeType::Server:
            imagePath = ":/images/SessionHavoc";
            break;
        default:
            imagePath = ":/images/unknown";
            break;
    }
    
    return QPixmap::fromImage( QImage( imagePath ) );
}

// ==================================================
// ============ NetworkDiagramManager ===============
// ==================================================

NetworkDiagramManager::NetworkDiagramManager( QWidget* parent ) : QWidget( parent )
{
    // Set save directory
    SaveDirectory = QCoreApplication::applicationDirPath() + "/../data/network_diagrams/";
    QDir().mkpath( SaveDirectory );
    
    setupUI();
    setupMenuBar();
    
    // Load all existing profiles from directory
    loadAllExistingProfiles();
    
    // If no profiles loaded, create default
    if ( TabWidget->count() == 0 )
    {
        createNewProfile( "Default" );
    }
}

NetworkDiagramManager::~NetworkDiagramManager()
{
    // Auto-save all profiles before closing
    saveAllProfiles();
}

void NetworkDiagramManager::setupUI()
{
    MainLayout = new QHBoxLayout( this );
    MainLayout->setContentsMargins( 0, 0, 0, 0 );
    MainLayout->setSpacing( 0 );
    
    // Create splitter for collapsible sidebar
    Splitter = new QSplitter( Qt::Horizontal, this );
    
    // Left sidebar
    Sidebar = new NetworkDiagramSidebar( this );
    Splitter->addWidget( Sidebar );
    
    // Right panel (menu bar + tabs)
    RightPanel = new QWidget( this );
    RightLayout = new QVBoxLayout( RightPanel );
    RightLayout->setContentsMargins( 0, 0, 0, 0 );
    RightLayout->setSpacing( 0 );
    
    TabWidget = new QTabWidget( RightPanel );
    TabWidget->setTabsClosable( true );
    TabWidget->setMovable( true );
    
    RightLayout->addWidget( TabWidget );
    Splitter->addWidget( RightPanel );
    
    // Set initial splitter sizes (sidebar smaller)
    Splitter->setStretchFactor( 0, 0 );
    Splitter->setStretchFactor( 1, 1 );
    Splitter->setSizes( QList<int>() << 150 << 1050 );
    
    MainLayout->addWidget( Splitter );
    
    connect( TabWidget, &QTabWidget::tabCloseRequested, this, &NetworkDiagramManager::onTabCloseRequested );
    
    // Connect sidebar node selection to add nodes
    connect( Sidebar, &NetworkDiagramSidebar::nodeTypeSelected, this, [this]( NetworkNodeType type ) {
        auto currentDiagram = getCurrentDiagram();
        if ( currentDiagram )
        {
            // Add node at center of view
            QPointF center = currentDiagram->mapToScene( currentDiagram->viewport()->rect().center() );
            
            bool ok;
            QString name = QInputDialog::getText( this, "New Node", "Enter node name:", 
                                                 QLineEdit::Normal, "NewNode", &ok );
            
            if ( ok && !name.isEmpty() )
            {
                QString ip = QInputDialog::getText( this, "New Node", "Enter IP address:", 
                                                   QLineEdit::Normal, "192.168.1.1", &ok );
                
                if ( ok && !ip.isEmpty() )
                {
                    currentDiagram->addNode( type, name, ip, center );
                }
            }
        }
    });
}

void NetworkDiagramManager::setupMenuBar()
{
    MenuBar = new QMenuBar( RightPanel );
    RightLayout->insertWidget( 0, MenuBar );
    
    auto MenuStyle = QString(
        "QMenuBar {"
        "    background-color: #282a36;"
        "    color: #f8f8f2;"
        "}"
        "QMenuBar::item:selected {"
        "    background: #44475a;"
        "}"
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
    );
    
    MenuBar->setStyleSheet( MenuStyle );
    
    // File menu
    QMenu* fileMenu = MenuBar->addMenu( "Profile" );
    fileMenu->setStyleSheet( MenuStyle );
    
    QAction* newProfileAction = fileMenu->addAction( "New Profile" );
    connect( newProfileAction, &QAction::triggered, this, &NetworkDiagramManager::onNewProfile );
    
    QAction* openProfileAction = fileMenu->addAction( "Open Profile" );
    connect( openProfileAction, &QAction::triggered, this, &NetworkDiagramManager::onOpenProfile );
    
    QAction* renameProfileAction = fileMenu->addAction( "Rename Current Profile" );
    connect( renameProfileAction, &QAction::triggered, this, &NetworkDiagramManager::onRenameProfile );
    
    fileMenu->addSeparator();
    
    QAction* saveAction = fileMenu->addAction( "Save Current Profile" );
    connect( saveAction, &QAction::triggered, this, &NetworkDiagramManager::onSaveProfile );
    
    QAction* saveAllAction = fileMenu->addAction( "Save All Profiles" );
    connect( saveAllAction, &QAction::triggered, this, &NetworkDiagramManager::saveAllProfiles );
    
    fileMenu->addSeparator();
    
    QAction* closeAction = fileMenu->addAction( "Close Current Profile" );
    connect( closeAction, &QAction::triggered, this, &NetworkDiagramManager::onCloseProfile );
}

void NetworkDiagramManager::createNewProfile( const QString& name )
{
    // Validate name
    QString profileName = name;
    if ( profileName.isEmpty() || profileName.contains( QChar( '\0' ) ) )
    {
        profileName = "Untitled";
    }
    
    // Check if profile already open
    for ( int i = 0; i < TabWidget->count(); i++ )
    {
        auto existingDiagram = qobject_cast<NetworkDiagramWidget*>( TabWidget->widget( i ) );
        if ( existingDiagram && existingDiagram->getProfileName() == profileName )
        {
            // Already open, just switch to it
            TabWidget->setCurrentIndex( i );
            return;
        }
    }
    
    // Create new diagram widget
    auto diagram = new NetworkDiagramWidget( this );
    diagram->setProfileName( profileName );
    
    // Try to load existing profile
    QString filePath = getProfileFilePath( profileName );
    if ( QFile::exists( filePath ) )
    {
        diagram->loadFromFile( filePath );
    }
    
    // Add to tabs
    int index = TabWidget->addTab( diagram, profileName );
    TabWidget->setCurrentIndex( index );
    
    // Connect auto-save on data changes
    connect( diagram, &NetworkDiagramWidget::dataChanged, this, &NetworkDiagramManager::saveCurrentProfile );
}

void NetworkDiagramManager::closeProfile( int index )
{
    if ( index < 0 || index >= TabWidget->count() )
        return;
    
    // Save before closing
    auto diagram = qobject_cast<NetworkDiagramWidget*>( TabWidget->widget( index ) );
    if ( diagram )
    {
        QString filePath = getProfileFilePath( diagram->getProfileName() );
        diagram->saveToFile( filePath );
    }
    
    // Remove tab
    TabWidget->removeTab( index );
    
    // If no tabs left, create default
    if ( TabWidget->count() == 0 )
    {
        createNewProfile( "Default" );
    }
}

void NetworkDiagramManager::renameProfile( int index, const QString& newName )
{
    if ( index < 0 || index >= TabWidget->count() )
        return;
    
    // Validate new name
    if ( newName.isEmpty() || newName.contains( QChar( '\0' ) ) )
        return;
    
    auto diagram = qobject_cast<NetworkDiagramWidget*>( TabWidget->widget( index ) );
    if ( diagram )
    {
        QString oldName = diagram->getProfileName();
        
        // Delete old file
        QString oldPath = getProfileFilePath( oldName );
        QFile::remove( oldPath );
        
        // Update name
        diagram->setProfileName( newName );
        TabWidget->setTabText( index, newName );
        
        // Save with new name
        QString newPath = getProfileFilePath( newName );
        diagram->saveToFile( newPath );
    }
}

void NetworkDiagramManager::saveCurrentProfile()
{
    auto diagram = getCurrentDiagram();
    if ( diagram )
    {
        QString filePath = getProfileFilePath( diagram->getProfileName() );
        diagram->saveToFile( filePath );
    }
}

void NetworkDiagramManager::saveAllProfiles()
{
    for ( int i = 0; i < TabWidget->count(); i++ )
    {
        auto diagram = qobject_cast<NetworkDiagramWidget*>( TabWidget->widget( i ) );
        if ( diagram )
        {
            QString filePath = getProfileFilePath( diagram->getProfileName() );
            diagram->saveToFile( filePath );
        }
    }
}

void NetworkDiagramManager::loadProfile( const QString& filename )
{
    QFile file( filename );
    if ( !file.exists() )
        return;
    
    // Read profile name from file
    if ( !file.open( QIODevice::ReadOnly ) )
        return;
    
    QByteArray data = file.readAll();
    file.close();
    
    QJsonDocument doc = QJsonDocument::fromJson( data );
    if ( doc.isNull() || !doc.isObject() )
        return;
    
    QJsonObject root = doc.object();
    QString profileName = root["profile_name"].toString();
    
    // Create new profile with this name
    createNewProfile( profileName );
}

NetworkDiagramWidget* NetworkDiagramManager::getCurrentDiagram()
{
    int index = TabWidget->currentIndex();
    if ( index < 0 )
        return nullptr;
    
    return qobject_cast<NetworkDiagramWidget*>( TabWidget->widget( index ) );
}

QString NetworkDiagramManager::getProfileFilePath( const QString& profileName )
{
    // Sanitize profile name for filename
    QString safeName = profileName;
    safeName.replace( "/", "_" );
    safeName.replace( "\\", "_" );
    safeName.replace( ":", "_" );
    
    return SaveDirectory + safeName + ".json";
}

void NetworkDiagramManager::onCloseProfile()
{
    int index = TabWidget->currentIndex();
    if ( index >= 0 )
    {
        closeProfile( index );
    }
}

void NetworkDiagramManager::onRenameProfile()
{
    int index = TabWidget->currentIndex();
    if ( index < 0 )
        return;
    
    auto diagram = qobject_cast<NetworkDiagramWidget*>( TabWidget->widget( index ) );
    if ( !diagram )
        return;
    
    bool ok;
    QString newName = QInputDialog::getText( this, "Rename Profile", "Enter new name:", 
                                            QLineEdit::Normal, diagram->getProfileName(), &ok );
    
    if ( ok && !newName.isEmpty() )
    {
        renameProfile( index, newName );
    }
}

void NetworkDiagramManager::onSaveProfile()
{
    saveCurrentProfile();
}

void NetworkDiagramManager::loadAllExistingProfiles()
{
    QDir dir( SaveDirectory );
    QStringList filters;
    filters << "*.json";
    dir.setNameFilters( filters );
    
    QFileInfoList files = dir.entryInfoList( QDir::Files );
    
    for ( const QFileInfo& fileInfo : files )
    {
        // Extract profile name from filename (remove .json extension)
        QString profileName = fileInfo.baseName();
        
        // Create and load profile
        auto diagram = new NetworkDiagramWidget( this );
        diagram->setProfileName( profileName );
        diagram->loadFromFile( fileInfo.absoluteFilePath() );
        
        // Add to tabs
        int index = TabWidget->addTab( diagram, profileName );
        
        // Connect auto-save
        connect( diagram, &NetworkDiagramWidget::dataChanged, this, &NetworkDiagramManager::saveCurrentProfile );
    }
}

void NetworkDiagramManager::onNewProfile()
{
    bool ok;
    QString name = QInputDialog::getText( this, "New Profile", "Enter profile name:", 
                                         QLineEdit::Normal, "NewProfile", &ok );
    
    if ( ok && !name.isEmpty() )
    {
        createNewProfile( name );
    }
}

void NetworkDiagramManager::onOpenProfile()
{
    // Scan directory for available profiles
    QDir dir( SaveDirectory );
    QStringList filters;
    filters << "*.json";
    dir.setNameFilters( filters );
    
    QFileInfoList files = dir.entryInfoList( QDir::Files );
    
    if ( files.isEmpty() )
    {
        QMessageBox::information( this, "No Profiles", "No saved profiles found in:\n" + SaveDirectory );
        return;
    }
    
    // Build list of profile names
    QStringList profileNames;
    for ( const QFileInfo& fileInfo : files )
    {
        QString profileName = fileInfo.baseName();
        
        // Check if already open
        bool alreadyOpen = false;
        for ( int i = 0; i < TabWidget->count(); i++ )
        {
            auto diagram = qobject_cast<NetworkDiagramWidget*>( TabWidget->widget( i ) );
            if ( diagram && diagram->getProfileName() == profileName )
            {
                alreadyOpen = true;
                break;
            }
        }
        
        if ( !alreadyOpen )
        {
            profileNames << profileName;
        }
    }
    
    if ( profileNames.isEmpty() )
    {
        QMessageBox::information( this, "All Profiles Open", "All saved profiles are already open." );
        return;
    }
    
    // Show selection dialog
    bool ok;
    QString selected = QInputDialog::getItem( this, "Open Profile", 
                                             "Select profile to open:", 
                                             profileNames, 0, false, &ok );
    
    if ( ok && !selected.isEmpty() )
    {
        createNewProfile( selected );
    }
}

void NetworkDiagramManager::onTabCloseRequested( int index )
{
    closeProfile( index );
}

void NetworkDiagramManager::closeEvent( QCloseEvent* event )
{
    // Save all profiles before closing
    saveAllProfiles();
    
    // Hide instead of close so we can reopen
    event->ignore();
    hide();
}
