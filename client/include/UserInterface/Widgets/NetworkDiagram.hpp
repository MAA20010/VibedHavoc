#ifndef HAVOC_NETWORKDIAGRAM_HPP
#define HAVOC_NETWORKDIAGRAM_HPP

#include <global.hpp>

#include <QGraphicsItem>
#include <QGraphicsView>
#include <QRect>
#include <QVector>
#include <QPointF>
#include <QWidget>
#include <QTabWidget>
#include <QMenuBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QSplitter>
#include <QPushButton>
#include <QLabel>
#include <QCloseEvent>

class NetworkNode;
class NetworkDiagramWidget;
class NetworkEdge;
class NetworkDiagramSidebar;
class NetworkDiagramManager;

enum class NetworkNodeType {
    Unknown     = 0,
    Windows11   = 1,
    Windows10   = 2,
    Windows7    = 3,
    WindowsXP   = 4,
    Linux       = 5,
    MacOS       = 6,
    Server      = 7
};

class NetworkNode : public QGraphicsItem
{
    QRectF         NodePainterSize = QRectF();
    QString        NodeName        = QString();
    QString        NodeIP          = QString();
    NetworkNodeType NodeType       = NetworkNodeType::Windows10;
    bool           IsCompromised   = false;
    bool           IsHighPrivilege = false;

public:
    NetworkNode( NetworkNodeType type, QString name, QString ip, NetworkDiagramWidget* diagramWidget );
    
    void setName( const QString& name );
    void setIP( const QString& ip );
    void setType( NetworkNodeType type );
    void setCompromised( bool compromised );
    void setHighPrivilege( bool highPriv );
    
    QString getName() const { return NodeName; }
    QString getIP() const { return NodeIP; }
    NetworkNodeType getType() const { return NodeType; }
    bool isCompromised() const { return IsCompromised; }
    bool isHighPrivilege() const { return IsHighPrivilege; }

    void addEdge( NetworkEdge* edge );
    void removeEdge( NetworkEdge* edge );
    QVector<NetworkEdge*> edges() const;
    
    void setSelected( bool selected );

    void contextMenuEvent( QGraphicsSceneContextMenuEvent* event ) override;

    enum { Type = UserType + 10 };
    int type() const override { return Type; }

    QRectF boundingRect() const override;
    QPainterPath shape() const override;

    void paint( QPainter* painter, const QStyleOptionGraphicsItem* option, QWidget* widget ) override;

protected:
    QVariant itemChange( GraphicsItemChange change, const QVariant& value ) override;

    void mousePressEvent( QGraphicsSceneMouseEvent* event ) override;
    void mouseReleaseEvent( QGraphicsSceneMouseEvent* event ) override;
    void mouseMoveEvent( QGraphicsSceneMouseEvent* event ) override;

private:
    QVector<NetworkEdge*> edgeList;
    NetworkDiagramWidget* diagram;
};

class NetworkDiagramWidget : public QGraphicsView
{
Q_OBJECT

    QGraphicsScene*           DiagramScene = nullptr;
    std::vector<NetworkNode*> NodeList     = std::vector<NetworkNode*>();
    QString                   ProfileName  = QString();

public:
    NetworkDiagramWidget( QWidget* parent = nullptr );
    ~NetworkDiagramWidget();
    
    void setProfileName( const QString& name ) { ProfileName = name; }
    QString getProfileName() const { return ProfileName; }

    void addNode( NetworkNodeType type, QString name, QString ip, QPointF position );
    void removeNode( NetworkNode* node );
    void editNode( NetworkNode* node, QString newName, QString newIP, NetworkNodeType newType );
    
    void addConnection( NetworkNode* source, NetworkNode* dest );
    void removeConnection( NetworkEdge* edge );
    void reverseEdgeDirection( NetworkEdge* edge );
    
    void clearAll();
    void saveToFile( const QString& filename );
    void loadFromFile( const QString& filename );
    
    QGraphicsScene* getScene() { return DiagramScene; }
    std::vector<NetworkNode*>& getNodes() { return NodeList; }

signals:
    void dataChanged();

public slots:
    void zoomIn();
    void zoomOut();

protected:
    void keyPressEvent( QKeyEvent* event ) override;
    void resizeEvent( QResizeEvent* event ) override;

#if QT_CONFIG( wheelevent )
    void wheelEvent( QWheelEvent* event ) override;
#endif

    void mousePressEvent( QMouseEvent* event ) override;
    void mouseMoveEvent( QMouseEvent* event ) override;
    void mouseReleaseEvent( QMouseEvent* event ) override;
    void contextMenuEvent( QContextMenuEvent* event ) override;

    void drawBackground( QPainter* painter, const QRectF& rect ) override;
    void scaleView( qreal scaleFactor );
    void updateDynamicSceneRect();

private:
    // Middle mouse button panning state
    bool isPanning = false;
    QPoint lastPanPoint;
    
    // For node connections
    NetworkNode* connectionSourceNode = nullptr;
    bool isConnecting = false;
};

class NetworkEdge : public QGraphicsItem
{
public:
    NetworkNode* source = nullptr;
    NetworkNode* dest   = nullptr;

    NetworkEdge( NetworkNode* sourceNode, NetworkNode* destNode );

    NetworkNode* sourceNode() const;
    NetworkNode* destNode() const;

    void adjust();
    void reverse();
    
    void contextMenuEvent( QGraphicsSceneContextMenuEvent* event ) override;

    enum { Type = UserType + 11 };
    int type() const override { return Type; }

protected:
    QRectF boundingRect() const override;
    void paint( QPainter* painter, const QStyleOptionGraphicsItem* option, QWidget* widget ) override;

private:
    QPointF sourcePoint = QPointF();
    QPointF destPoint   = QPointF();
    qreal   arrowSize   = 10;
    QColor  color       = QColor( 0x50fa7b ); // Green
};

// Sidebar widget with draggable node icons
class NetworkDiagramSidebar : public QWidget
{
Q_OBJECT

    QVBoxLayout*     MainLayout     = nullptr;
    QScrollArea*     ScrollArea     = nullptr;
    QWidget*         ContentWidget  = nullptr;
    QVBoxLayout*     ContentLayout  = nullptr;

public:
    NetworkDiagramSidebar( QWidget* parent = nullptr );
    
signals:
    void nodeTypeSelected( NetworkNodeType type );

private:
    void setupNodeButtons();
    QPixmap getNodeIcon( NetworkNodeType type );
};

// Manager widget that holds multiple diagram profiles in tabs
class NetworkDiagramManager : public QWidget
{
Q_OBJECT

    QHBoxLayout*     MainLayout     = nullptr;
    QSplitter*       Splitter       = nullptr;
    NetworkDiagramSidebar* Sidebar  = nullptr;
    QWidget*         RightPanel     = nullptr;
    QVBoxLayout*     RightLayout    = nullptr;
    QMenuBar*        MenuBar        = nullptr;
    QTabWidget*      TabWidget      = nullptr;
    QString          SaveDirectory  = QString();

public:
    NetworkDiagramManager( QWidget* parent = nullptr );
    ~NetworkDiagramManager();
    
    void createNewProfile( const QString& name );
    void closeProfile( int index );
    void renameProfile( int index, const QString& newName );
    void saveCurrentProfile();
    void saveAllProfiles();
    void loadProfile( const QString& filename );
    void loadAllExistingProfiles();
    
    NetworkDiagramWidget* getCurrentDiagram();
    
protected:
    void closeEvent( QCloseEvent* event ) override;
    
private:
    void setupMenuBar();
    void setupUI();
    QString getProfileFilePath( const QString& profileName );
    
private slots:
    void onNewProfile();
    void onOpenProfile();
    void onCloseProfile();
    void onRenameProfile();
    void onSaveProfile();
    void onTabCloseRequested( int index );
};

#endif

