#include <UserInterface/Dialogs/AdminFeatureDialog.hpp>

AdminFeatureDialog::AdminFeatureDialog(const QString& title, const QString& message, QWidget* parent)
    : QDialog(parent), dialogTitle(title), dialogMessage(message)
{
    setupUi();
    setModal(true);
    setAttribute(Qt::WA_DeleteOnClose);
}

void AdminFeatureDialog::setupUi()
{
    setObjectName("AdminFeatureDialog");
    setWindowTitle(dialogTitle);
    setFixedSize(400, 200);
    
    // Apply Havoc's dark theme styling
    // Admin tab popups window
    setStyleSheet(R"(
        QDialog#AdminFeatureDialog {
            background-color: #2b2b2b;
            color: #ffffff;
            border: 2px solid #404040;
            border-radius: 8px;
        }
        
        QLabel {
            color: #ffffff;
            background-color: transparent;
            border: none;
        }
        
        QLabel#titleLabel {
            font-size: 16px;
            font-weight: bold;
            color: #61dafb;
            margin-bottom: 10px;
        }
        
        QLabel#messageLabel {
            font-size: 14px;
            color: #cccccc;
            margin: 10px 0;
        }
        
        QPushButton {
            background-color: #404040;
            color: #ffffff;
            border: 1px solid #606060;
            border-radius: 6px;
            padding: 8px 16px;
            font-size: 13px;
            font-weight: bold;
            min-width: 80px;
        }
        
        QPushButton:hover {
            background-color: #4a4a4a;
            border: 1px solid #61dafb;
        }
        
        QPushButton:pressed {
            background-color: #3a3a3a;
            border: 1px solid #61dafb;
        }
        
        QPushButton:focus {
            outline: none;
            border: 1px solid #61dafb;
        }
    )");

    // Main layout
    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    // Title label
    titleLabel = new QLabel(dialogTitle);
    titleLabel->setObjectName("titleLabel");
    titleLabel->setAlignment(Qt::AlignCenter);
    
    // Message label
    messageLabel = new QLabel(dialogMessage);
    messageLabel->setObjectName("messageLabel");
    messageLabel->setAlignment(Qt::AlignCenter);
    messageLabel->setWordWrap(true);

    // OK button
    okButton = new QPushButton("OK");
    okButton->setDefault(true);
    okButton->setFocus();
    
    // Button layout
    buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    buttonLayout->addWidget(okButton);
    buttonLayout->addStretch();

    // Add widgets to main layout
    mainLayout->addWidget(titleLabel);
    mainLayout->addWidget(messageLabel);
    mainLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    // Connect signals
    connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
    
    // Handle Escape key
    connect(this, &QDialog::rejected, this, &QDialog::close);
}
