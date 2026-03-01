#include <UserInterface/Dialogs/AgentAssignmentDialog.hpp>
#include <global.hpp>
#include <QTimer>

using namespace HavocNamespace::UserInterface::Dialogs;

AgentAssignmentDialog::AgentAssignmentDialog(const QString& username, const QString& sessionToken, QWidget* parent)
    : QDialog(parent), targetUsername(username), sessionToken(sessionToken), networkManager(new QNetworkAccessManager(this))
{
    setupUi();
    
    // Configure SSL for self-signed certificates
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
    QSslConfiguration::setDefaultConfiguration(sslConfig);
    
    // Connect network signals
    connect(networkManager, &QNetworkAccessManager::finished, this, &AgentAssignmentDialog::onNetworkReplyFinished);
    
    // Ignore SSL errors (teamserver uses self-signed cert)
    connect(networkManager, &QNetworkAccessManager::sslErrors,
            [](QNetworkReply* reply, const QList<QSslError>& errors) {
                reply->ignoreSslErrors(errors);
            });
    
    // Load data after UI initialized
    QTimer::singleShot(100, this, &AgentAssignmentDialog::loadAgentLists);
}

AgentAssignmentDialog::~AgentAssignmentDialog()
{
    if (currentReply) {
        currentReply->abort();
        currentReply->deleteLater();
    }
}

void AgentAssignmentDialog::setupUi()
{
    setObjectName("AgentAssignmentDialog");
    setWindowTitle(QString("Agent Assignment - %1").arg(targetUsername));
    setFixedSize(800, 500);
    setModal(true);
    
    // Apply dark theme styling
    setStyleSheet(R"(
        QDialog#AgentAssignmentDialog {
            background-color: #2b2b2b;
            color: #ffffff;
            border: 2px solid #404040;
            border-radius: 8px;
        }
        
        QLabel {
            color: #ffffff;
            font-size: 14px;
            font-weight: bold;
            padding: 5px;
        }
        
        QListWidget {
            background-color: #333333;
            color: #ffffff;
            border: 1px solid #606060;
            border-radius: 4px;
            selection-background-color: #61dafb;
            selection-color: #000000;
            padding: 5px;
        }
        
        QListWidget::item {
            padding: 5px;
            border-bottom: 1px solid #404040;
        }
        
        QListWidget::item:hover {
            background-color: #3a3a3a;
        }
        
        QPushButton {
            background-color: #404040;
            color: #ffffff;
            border: 1px solid #606060;
            border-radius: 6px;
            padding: 8px 16px;
            font-size: 13px;
            font-weight: bold;
            min-width: 100px;
        }
        
        QPushButton:hover {
            background-color: #4a4a4a;
            border: 1px solid #61dafb;
        }
        
        QPushButton:pressed {
            background-color: #3a3a3a;
        }
        
        QPushButton:disabled {
            background-color: #2a2a2a;
            color: #666666;
            border: 1px solid #404040;
        }
        
        #statusLabel {
            color: #cccccc;
            font-weight: normal;
            font-size: 12px;
        }
    )");
    
    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(15, 15, 15, 15);
    mainLayout->setSpacing(10);
    
    // Status label
    statusLabel = new QLabel("Loading agents...");
    statusLabel->setObjectName("statusLabel");
    statusLabel->setAlignment(Qt::AlignRight);
    mainLayout->addWidget(statusLabel);
    
    // Lists layout
    listsLayout = new QHBoxLayout();
    listsLayout->setSpacing(15);
    
    // Available agents (left side)
    QVBoxLayout* availableLayout = new QVBoxLayout();
    availableLabel = new QLabel("Available Agents");
    availableAgentsList = new QListWidget();
    availableAgentsList->setSelectionMode(QAbstractItemView::SingleSelection);
    availableLayout->addWidget(availableLabel);
    availableLayout->addWidget(availableAgentsList);
    
    // Assigned agents (right side)
    QVBoxLayout* assignedLayout = new QVBoxLayout();
    assignedLabel = new QLabel("Assigned Agents");
    assignedAgentsList = new QListWidget();
    assignedAgentsList->setSelectionMode(QAbstractItemView::SingleSelection);
    assignedLayout->addWidget(assignedLabel);
    assignedLayout->addWidget(assignedAgentsList);
    
    listsLayout->addLayout(availableLayout);
    listsLayout->addLayout(assignedLayout);
    
    mainLayout->addLayout(listsLayout);
    
    // Action buttons (Assign/Revoke)
    actionButtonLayout = new QHBoxLayout();
    actionButtonLayout->setSpacing(10);
    
    assignButton = new QPushButton("Assign →");
    assignButton->setEnabled(false);
    revokeButton = new QPushButton("← Revoke");
    revokeButton->setEnabled(false);
    
    actionButtonLayout->addStretch();
    actionButtonLayout->addWidget(assignButton);
    actionButtonLayout->addWidget(revokeButton);
    actionButtonLayout->addStretch();
    
    mainLayout->addLayout(actionButtonLayout);
    
    // Bottom buttons
    buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(10);
    
    refreshButton = new QPushButton("Refresh");
    closeButton = new QPushButton("Close");
    
    buttonLayout->addWidget(refreshButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(closeButton);
    
    mainLayout->addLayout(buttonLayout);
    
    // Connect button signals
    connect(assignButton, &QPushButton::clicked, this, &AgentAssignmentDialog::onAssignButtonClicked);
    connect(revokeButton, &QPushButton::clicked, this, &AgentAssignmentDialog::onRevokeButtonClicked);
    connect(refreshButton, &QPushButton::clicked, this, &AgentAssignmentDialog::onRefreshButtonClicked);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::reject);
    
    // Connect list selection signals
    connect(availableAgentsList, &QListWidget::itemSelectionChanged, this, &AgentAssignmentDialog::onAvailableAgentSelectionChanged);
    connect(assignedAgentsList, &QListWidget::itemSelectionChanged, this, &AgentAssignmentDialog::onAssignedAgentSelectionChanged);
}

void AgentAssignmentDialog::loadAgentLists()
{
    // DEFENSIVE: Validate UI components before accessing
    if (!statusLabel || !availableAgentsList || !assignedAgentsList) {
        qWarning() << "[AgentAssignmentDialog] Critical UI components not initialized";
        return;
    }
    
    statusLabel->setText("Loading agents...");
    
    // First, get all available agents from the teamserver sessions
    availableAgentsList->clear();
    
    // DEFENSIVE: Check if Sessions vector exists and is accessible
    try {
        auto Sessions = HavocX::Teamserver.Sessions;
        
        // DEFENSIVE: Check if Sessions is empty
        if (Sessions.empty()) {
            qDebug() << "[AgentAssignmentDialog] No active sessions available";
            statusLabel->setText("No active agents found");
        } else {
            // DEFENSIVE: Validate each session before accessing
            for (const auto& session : Sessions) {
                // NULL BYTE CHECK: Ensure Name is valid and doesn't contain null bytes
                QString sessionName = session.Name;
                
                if (sessionName.isEmpty()) {
                    qWarning() << "[AgentAssignmentDialog] Skipping session with empty name";
                    continue;
                }
                
                // Remove any null bytes from the string (defensive against corrupted data)
                sessionName = sessionName.replace(QChar('\0'), QString());
                
                if (sessionName.isEmpty()) {
                    qWarning() << "[AgentAssignmentDialog] Session name contained only null bytes, skipped";
                    continue;
                }
                
                availableAgentsList->addItem(sessionName);
            }
        }
    } catch (const std::exception& e) {
        qCritical() << "[AgentAssignmentDialog] Exception accessing Sessions:" << e.what();
        statusLabel->setText("Error loading agents");
        showErrorMessage("Error", QString("Failed to load agents: %1").arg(e.what()));
        return;
    } catch (...) {
        qCritical() << "[AgentAssignmentDialog] Unknown exception accessing Sessions";
        statusLabel->setText("Error loading agents");
        showErrorMessage("Error", "Unknown error occurred while loading agents");
        return;
    }
    
    // DEFENSIVE: Validate sessionToken before making API request
    if (sessionToken.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] No session token available";
        statusLabel->setText("Authentication error");
        showErrorMessage("Error", "No session token available for API request");
        return;
    }
    
    // DEFENSIVE: Validate targetUsername before using in API request
    if (targetUsername.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] No target username provided";
        statusLabel->setText("Configuration error");
        showErrorMessage("Error", "No username provided for assignment");
        return;
    }
    
    // NULL BYTE CHECK: Ensure targetUsername doesn't contain null bytes
    QString cleanUsername = targetUsername;
    cleanUsername = cleanUsername.replace(QChar('\0'), QString());
    
    if (cleanUsername.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Username contained only null bytes";
        statusLabel->setText("Invalid username");
        showErrorMessage("Error", "Invalid username format");
        return;
    }
    
    // Now get assigned agents from API
    currentRequestType = "load_assigned";
    QString endpoint = QString("/auth/agents/assigned?username=%1").arg(cleanUsername);
    makeApiRequest(endpoint, "GET");
}

void AgentAssignmentDialog::makeApiRequest(const QString& endpoint, const QString& method, const QJsonObject& data)
{
    // DEFENSIVE: Validate networkManager before use
    if (!networkManager) {
        qCritical() << "[AgentAssignmentDialog] NetworkManager not initialized";
        showErrorMessage("Error", "Network manager not initialized");
        return;
    }
    
    // DEFENSIVE: Validate endpoint
    if (endpoint.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Empty endpoint provided";
        showErrorMessage("Error", "Invalid API endpoint");
        return;
    }
    
    // NULL BYTE CHECK: Clean endpoint
    QString cleanEndpoint = endpoint;
    cleanEndpoint = cleanEndpoint.replace(QChar('\0'), QString());
    
    if (cleanEndpoint.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Endpoint contained only null bytes";
        showErrorMessage("Error", "Invalid endpoint format");
        return;
    }
    
    // DEFENSIVE: Validate Host and Port
    QString host = HavocX::Teamserver.Host;
    QString port = HavocX::Teamserver.Port;
    
    if (host.isEmpty() || port.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Teamserver host or port not configured";
        showErrorMessage("Error", "Teamserver connection not configured");
        return;
    }
    
    // NULL BYTE CHECK: Clean host and port
    host = host.replace(QChar('\0'), QString());
    port = port.replace(QChar('\0'), QString());
    
    QString baseUrl = QString("https://%1:%2").arg(host).arg(port);
    QUrl url(baseUrl + cleanEndpoint);
    
    // DEFENSIVE: Validate URL
    if (!url.isValid()) {
        qWarning() << "[AgentAssignmentDialog] Invalid URL:" << url.toString();
        showErrorMessage("Error", "Invalid server URL");
        return;
    }
    
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    // Add Bearer token authentication
    if (!sessionToken.isEmpty()) {
        // NULL BYTE CHECK: Clean session token
        QString cleanToken = sessionToken;
        cleanToken = cleanToken.replace(QChar('\0'), QString());
        
        if (!cleanToken.isEmpty()) {
            request.setRawHeader("Authorization", QString("Bearer %1").arg(cleanToken).toUtf8());
        } else {
            qWarning() << "[AgentAssignmentDialog] Session token contained only null bytes";
        }
    }
    
    // RACE CONDITION PREVENTION: Cancel any existing request before starting new one
    if (currentReply != nullptr) {
        qDebug() << "[AgentAssignmentDialog] Aborting previous network request";
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }
    
    // Make request based on method
    try {
        if (method == "GET") {
            currentReply = networkManager->get(request);
        } else if (method == "POST") {
            QJsonDocument doc(data);
            currentReply = networkManager->post(request, doc.toJson());
        } else {
            qWarning() << "[AgentAssignmentDialog] Unsupported HTTP method:" << method;
            showErrorMessage("Error", QString("Unsupported HTTP method: %1").arg(method));
            return;
        }
        
        // DEFENSIVE: Validate reply was created
        if (!currentReply) {
            qCritical() << "[AgentAssignmentDialog] Failed to create network reply";
            showErrorMessage("Error", "Failed to create network request");
        }
    } catch (const std::exception& e) {
        qCritical() << "[AgentAssignmentDialog] Exception during network request:" << e.what();
        showErrorMessage("Error", QString("Network request failed: %1").arg(e.what()));
    } catch (...) {
        qCritical() << "[AgentAssignmentDialog] Unknown exception during network request";
        showErrorMessage("Error", "Unknown network error occurred");
    }
}

void AgentAssignmentDialog::onNetworkReplyFinished()
{
    // DEFENSIVE: Validate reply exists
    if (!currentReply) {
        qDebug() << "[AgentAssignmentDialog] Reply finished but currentReply is null";
        return;
    }
    
    // DEFENSIVE: Validate statusLabel exists before using
    if (!statusLabel) {
        qWarning() << "[AgentAssignmentDialog] statusLabel is null in onNetworkReplyFinished";
        currentReply->deleteLater();
        currentReply = nullptr;
        return;
    }
    
    QNetworkReply::NetworkError error = currentReply->error();
    QString errorString = currentReply->errorString();  // Save before deleting reply
    int statusCode = currentReply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    QByteArray responseData = currentReply->readAll();
    
    // DEFENSIVE: Clean up reply immediately to prevent race conditions
    currentReply->deleteLater();
    currentReply = nullptr;
    
    if (error != QNetworkReply::NoError) {
        statusLabel->setText("Network error");
        showErrorMessage("Network Error", QString("Error: %1").arg(errorString));
        return;
    }
    
    if (statusCode != 200) {
        statusLabel->setText("Request failed");
        showErrorMessage("Error", QString("Server returned status: %1").arg(statusCode));
        return;
    }
    
    // DEFENSIVE: Validate response data
    if (responseData.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Empty response from server";
        statusLabel->setText("Empty response");
        showErrorMessage("Error", "Server returned empty response");
        return;
    }
    
    // NULL BYTE CHECK: Remove null bytes from response
    responseData = responseData.replace('\0', "");
    
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(responseData, &parseError);
    
    // DEFENSIVE: Validate JSON parsing
    if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "[AgentAssignmentDialog] JSON parse error:" << parseError.errorString();
        statusLabel->setText("Invalid response");
        showErrorMessage("Error", QString("Invalid JSON response: %1").arg(parseError.errorString()));
        return;
    }
    
    if (!doc.isObject()) {
        qWarning() << "[AgentAssignmentDialog] Response is not a JSON object";
        statusLabel->setText("Invalid response format");
        showErrorMessage("Error", "Response is not a valid JSON object");
        return;
    }
    
    QJsonObject obj = doc.object();
    
    if (!obj.contains("success")) {
        qWarning() << "[AgentAssignmentDialog] Response missing 'success' field";
        statusLabel->setText("Invalid response");
        showErrorMessage("Error", "Response missing success field");
        return;
    }
    
    if (!obj["success"].toBool()) {
        QString errorMsg = obj.contains("message") ? obj["message"].toString() : "Unknown error";
        statusLabel->setText("Request failed");
        showErrorMessage("Error", errorMsg);
        return;
    }
    
    // Handle different request types
    if (currentRequestType == "load_assigned") {
        // DEFENSIVE: Validate assignedAgentsList before using
        if (!assignedAgentsList) {
            qWarning() << "[AgentAssignmentDialog] assignedAgentsList is null";
            return;
        }
        
        assignedAgentsList->clear();
        
        if (obj.contains("agent_ids") && obj["agent_ids"].isArray()) {
            QJsonArray agentIDs = obj["agent_ids"].toArray();
            for (const auto& agentID : agentIDs) {
                QString agentStr = agentID.toString();
                
                // NULL BYTE CHECK: Clean agent ID
                agentStr = agentStr.replace(QChar('\0'), QString());
                
                if (!agentStr.isEmpty()) {
                    assignedAgentsList->addItem(agentStr);
                }
            }
        }
        
        // DEFENSIVE: Validate lists before accessing count
        int availableCount = availableAgentsList ? availableAgentsList->count() : 0;
        int assignedCount = assignedAgentsList ? assignedAgentsList->count() : 0;
        
        statusLabel->setText(QString("Loaded: %1 available, %2 assigned")
                            .arg(availableCount)
                            .arg(assignedCount));
    }
    else if (currentRequestType == "assign") {
        statusLabel->setText("Agent assigned successfully");
        statusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
        
        // DEFENSIVE: Check if dialog still exists before timer callback
        QTimer::singleShot(3000, this, [this]() {
            if (statusLabel) {
                statusLabel->setStyleSheet("color: #cccccc; font-weight: normal;");
            }
        });
        
        loadAgentLists();  // Refresh lists
    }
    else if (currentRequestType == "revoke") {
        statusLabel->setText("Agent revoked successfully");
        statusLabel->setStyleSheet("color: #4CAF50; font-weight: bold;");
        
        // DEFENSIVE: Check if dialog still exists before timer callback
        QTimer::singleShot(3000, this, [this]() {
            if (statusLabel) {
                statusLabel->setStyleSheet("color: #cccccc; font-weight: normal;");
            }
        });
        
        loadAgentLists();  // Refresh lists
    }
}

void AgentAssignmentDialog::onAssignButtonClicked()
{
    // DEFENSIVE: Validate UI components
    if (!availableAgentsList || !assignButton) {
        qWarning() << "[AgentAssignmentDialog] UI components not initialized in onAssignButtonClicked";
        return;
    }
    
    QListWidgetItem* selectedItem = availableAgentsList->currentItem();
    if (!selectedItem) {
        qDebug() << "[AgentAssignmentDialog] No agent selected for assignment";
        showErrorMessage("No Selection", "Please select an agent to assign");
        return;
    }
    
    QString agentID = selectedItem->text();
    
    // DEFENSIVE: Validate agent ID
    if (agentID.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Selected agent has empty ID";
        showErrorMessage("Error", "Invalid agent selection");
        return;
    }
    
    // NULL BYTE CHECK: Clean agent ID
    agentID = agentID.replace(QChar('\0'), QString());
    
    if (agentID.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Agent ID contained only null bytes";
        showErrorMessage("Error", "Invalid agent ID format");
        return;
    }
    
    // DEFENSIVE: Validate targetUsername
    if (targetUsername.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Target username is empty";
        showErrorMessage("Error", "No username configured for assignment");
        return;
    }
    
    QJsonObject data;
    data["username"] = targetUsername;
    data["agent_id"] = agentID;
    
    currentRequestType = "assign";
    makeApiRequest("/auth/agents/assign", "POST", data);
    
    // DEFENSIVE: Check button still exists before modifying
    if (assignButton) {
        assignButton->setEnabled(false);
        assignButton->setText("Assigning...");
    }
}

void AgentAssignmentDialog::onRevokeButtonClicked()
{
    // DEFENSIVE: Validate UI components
    if (!assignedAgentsList || !revokeButton) {
        qWarning() << "[AgentAssignmentDialog] UI components not initialized in onRevokeButtonClicked";
        return;
    }
    
    QListWidgetItem* selectedItem = assignedAgentsList->currentItem();
    if (!selectedItem) {
        qDebug() << "[AgentAssignmentDialog] No agent selected for revocation";
        showErrorMessage("No Selection", "Please select an assigned agent to revoke");
        return;
    }
    
    QString agentID = selectedItem->text();
    
    // DEFENSIVE: Validate agent ID
    if (agentID.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Selected agent has empty ID";
        showErrorMessage("Error", "Invalid agent selection");
        return;
    }
    
    // NULL BYTE CHECK: Clean agent ID
    agentID = agentID.replace(QChar('\0'), QString());
    
    if (agentID.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Agent ID contained only null bytes";
        showErrorMessage("Error", "Invalid agent ID format");
        return;
    }
    
    // DEFENSIVE: Validate targetUsername
    if (targetUsername.isEmpty()) {
        qWarning() << "[AgentAssignmentDialog] Target username is empty";
        showErrorMessage("Error", "No username configured for revocation");
        return;
    }
    
    QJsonObject data;
    data["username"] = targetUsername;
    data["agent_id"] = agentID;
    
    currentRequestType = "revoke";
    makeApiRequest("/auth/agents/revoke", "POST", data);
    
    // DEFENSIVE: Check button still exists before modifying
    if (revokeButton) {
        revokeButton->setEnabled(false);
        revokeButton->setText("Revoking...");
    }
}

void AgentAssignmentDialog::onRefreshButtonClicked()
{
    loadAgentLists();
}

void AgentAssignmentDialog::onAvailableAgentSelectionChanged()
{
    bool hasSelection = availableAgentsList->currentItem() != nullptr;
    assignButton->setEnabled(hasSelection);
    assignButton->setText("Assign →");
}

void AgentAssignmentDialog::onAssignedAgentSelectionChanged()
{
    bool hasSelection = assignedAgentsList->currentItem() != nullptr;
    revokeButton->setEnabled(hasSelection);
    revokeButton->setText("← Revoke");
}

void AgentAssignmentDialog::showErrorMessage(const QString& title, const QString& message)
{
    QMessageBox msgBox(this);
    msgBox.setWindowTitle(title);
    msgBox.setText(message);
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setStandardButtons(QMessageBox::Ok);
    
    msgBox.setStyleSheet(R"(
        QMessageBox {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QMessageBox QPushButton {
            background-color: #404040;
            color: #ffffff;
            border: 1px solid #606060;
            border-radius: 6px;
            padding: 8px 16px;
        }
        QMessageBox QPushButton:hover {
            background-color: #4a4a4a;
            border: 1px solid #61dafb;
        }
    )");
    
    msgBox.exec();
}

