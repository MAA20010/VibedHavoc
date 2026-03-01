#include <global.hpp>
#include <UserInterface/Widgets/Chat.hpp>
#include <Util/ColorText.h>
#include <QtCore>
#include <QCompleter>
#include <QAbstractItemModel>

#include <Havoc/Packager.hpp>
#include <Havoc/Connector.hpp>

void HavocNamespace::UserInterface::Widgets::Chat::setupUi( QWidget *Form )
{
    ChatWidget = Form;

    if ( Form->objectName().isEmpty() ) {
        Form->setObjectName(QString::fromUtf8("Form"));
    }

    Form->resize( 932, 536 );

    gridLayout = new QGridLayout(Form);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    gridLayout->setVerticalSpacing(4);
    gridLayout->setContentsMargins(1, 4, 1, 4);
    lineEdit = new ChatInputEdit(Form);
    lineEdit->setObjectName(QString::fromUtf8("lineEdit"));

    gridLayout->addWidget(lineEdit, 2, 1, 1, 1);

    auto label = new QLabel(Form);
    label->setObjectName(QString::fromUtf8("label"));

    gridLayout->addWidget(label, 2, 0, 1, 1);

    EventLogText = new QTextEdit(Form);
    EventLogText->setObjectName(QString::fromUtf8("EventLogText"));
    EventLogText->setReadOnly(true);
    EventLogText->setLineWrapMode(QTextEdit::WidgetWidth);   // Wrap at widget boundary
    EventLogText->setWordWrapMode(QTextOption::WrapAnywhere); // Break anywhere (even mid-word)

    gridLayout->addWidget(EventLogText, 0, 0, 1, 2);

    Form->setWindowTitle(QCoreApplication::translate("Form", "Form", nullptr));
    lineEdit->setText(QString());

    label->setStyleSheet("padding-bottom: 3px; padding-left: 5px;");

    lineEdit->setStyleSheet(
            "background-color: "+Util::ColorText::Colors::Hex::Background+";"
            + "color: "+Util::ColorText::Colors::Hex::Foreground+";"
            );

    EventLogText->setStyleSheet(
            "background-color: "+Util::ColorText::Colors::Hex::Background+";"
            + "color: "+Util::ColorText::Colors::Hex::Foreground+";"
            );

    label->setText( HavocX::Teamserver.User );
    connect( lineEdit, &ChatInputEdit::returnPressed, this, &Chat::AppendFromInput );

    QMetaObject::connectSlotsByName(Form);
}

void HavocNamespace::UserInterface::Widgets::Chat::AppendText(const QString& Time, const QString& text) const
{
    QString t = Util::ColorText::Comment(Time) +" "+ text;

    EventLogText->append( t );
}

void HavocNamespace::UserInterface::Widgets::Chat::AddUserMessage(const QString Time, QString User, QString text) const
{
    // Modern block layout with consistent spacing
    // Format:
    //   Username • HH:MM:SS
    //   Message content here
    //   Multiple lines flow naturally
    
    QString displayText = text;
    displayText.replace("\n", "<br>");
    
    // Extract just the time (HH:MM:SS) from full timestamp
    QString timeOnly = Time;
    if (Time.contains(" ")) {
        timeOnly = Time.split(" ").last(); // Get time part after date
    }
    
    // Consistent styling with proper spacing
    QString containerStyle = "margin-bottom: 12px; padding-left: 8px; border-left: 3px solid transparent;";
    QString headerStyle = "font-weight: bold; color: #87CEEB; margin-bottom: 4px;";  // Light blue
    QString timeStyle = "color: #888; font-weight: normal; font-size: 11px;";
    QString messageStyle = "padding-left: 4px; line-height: 1.4;";
    
    QString message;
    
    if ( HavocX::Teamserver.User.compare( User ) == 0 ) {
        // Current user - green username with accent border
        message = QString("<div style='%1 border-left-color: #4CAF50;'>"
                         "<div style='%2'><span style='color: #4CAF50;'>%3</span> <span style='%4'>• %5</span></div>"
                         "<div style='%6'>%7</div>"
                         "</div>")
                    .arg(containerStyle)
                    .arg(headerStyle)
                    .arg(User)
                    .arg(timeStyle)
                    .arg(timeOnly)
                    .arg(messageStyle)
                    .arg(displayText);
    } else {
        // Other user - blue username with accent border
        message = QString("<div style='%1 border-left-color: #2196F3;'>"
                         "<div style='%2'>%3 <span style='%4'>• %5</span></div>"
                         "<div style='%6'>%7</div>"
                         "</div>")
                    .arg(containerStyle)
                    .arg(headerStyle)
                    .arg(User)
                    .arg(timeStyle)
                    .arg(timeOnly)
                    .arg(messageStyle)
                    .arg(displayText);
    }
    
    EventLogText->append(message);
}

void HavocNamespace::UserInterface::Widgets::Chat::AppendFromInput()
{
    auto text = this->lineEdit->toPlainText();

    if ( ! text.isEmpty() )
    {
        Util::Packager::Package Package;

        Util::Packager::Head_t Head;
        Util::Packager::Body_t Body;

        auto User = HavocX::Teamserver.User.toStdString();

        Head.Event        = Util::Packager::Chat::Type;
        Head.Time         = QTime::currentTime().toString("hh:mm:ss").toStdString();
        Head.User         = User;
        Body.SubEvent     = Util::Packager::Chat::NewMessage;
        Body.Info[ User ] = text.toHtmlEscaped().toUtf8().toBase64().toStdString();

        Package.Head = Head;
        Package.Body = Body;

        HavocX::Connector->SendPackage( &Package );
    }

    this->lineEdit->clear();
}
