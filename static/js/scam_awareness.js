// Re-verify the helpline number and portal address before submission.
const awarenessContent = {
    en: {
        eyebrow: "PAUSE, CHECK, VERIFY",
        title: "Learn the signs. Choose a safer next step.",
        introduction: "Scam messages and calls often create urgency, fear, or excitement. Review these examples, verify requests independently, and never share sensitive information under pressure.",
        topicsTitle: "Common scam topics",
        searchLabel: "Search scam topics",
        searchPlaceholder: "Search by topic or warning sign",
        filtersLabel: "Filter scam topics",
        allTopics: "All topics",
        noMatches: "No topics match your search. Try another word or filter.",
        howItWorks: "How it works",
        warningSigns: "Warning signs",
        whatToDo: "What to do",
        topics: [
            { id: "banking", label: "Bank and KYC messages" },
            { id: "credentials", label: "OTP and UPI PIN theft" },
            { id: "prizes", label: "Lottery and prize scams" },
            { id: "jobs", label: "Fake job offers" },
            { id: "delivery", label: "Delivery and customs scams" },
            { id: "payments", label: "UPI collect and refund scams" },
            { id: "customer-care", label: "Fake customer-care numbers" },
            { id: "loan-apps", label: "Loan-app harassment" },
            { id: "officials", label: "Impersonation and digital-arrest calls" },
        ],
        cards: [
            {
                category: "banking",
                title: "Fake bank KYC or account-block messages",
                how: "A message claims your bank account, card, or KYC will be blocked soon. It pushes you to use a link or call a number supplied in the message.",
                warnings: [
                    "A sudden deadline or threat to freeze your account.",
                    "A link asking you to sign in, update KYC, or enter card details.",
                    "Requests for an OTP, PIN, password, or remote access.",
                ],
                actions: [
                    "Do not use the message link or phone number.",
                    "Open your bank's official app or type its known website address yourself.",
                    "Call the number printed on your card or listed on the official website.",
                ],
            },
            {
                category: "credentials",
                title: "OTP and UPI PIN theft",
                how: "Someone pretends an OTP is needed to cancel a payment, receive a refund, or verify your identity. A fraudster may also ask you to approve a UPI collect request or share your UPI PIN.",
                warnings: [
                    "A caller or message asks you to read out an OTP, PIN, or CVV.",
                    "You are told to approve a collect request to receive money.",
                    "A person asks you to screen-share or install a support app.",
                ],
                actions: [
                    "Never share an OTP, UPI PIN, password, or CVV with anyone.",
                    "Read the UPI app screen carefully; approving a collect request can send money.",
                    "End the call and contact your bank through its official app or known number.",
                ],
            },
            {
                category: "prizes",
                title: "Lottery and prize scams",
                how: "An unexpected message says you won a lottery, gift, or prize. The sender asks for a fee, tax, or personal details before releasing it.",
                warnings: [
                    "You are told you won a contest you never entered.",
                    "You must pay a processing, tax, or delivery fee first.",
                    "The sender asks for banking details, an OTP, or a link click.",
                ],
                actions: [
                    "Do not pay money or share personal or banking details to claim a surprise prize.",
                    "Check the offer using the organiser's official website or contact details.",
                ],
            },
            {
                category: "jobs",
                title: "Fake job offers with registration fees",
                how: "A recruiter promises a job, high income, or easy work-from-home tasks. They may demand a registration, training, interview, or equipment fee.",
                warnings: [
                    "A job is offered without a credible interview or company details.",
                    "You are asked to pay to secure a role, task, or interview.",
                    "The recruiter uses a personal email or pressures you to act quickly.",
                ],
                actions: [
                    "Verify the vacancy on the employer's official careers page.",
                    "Do not pay an upfront fee or share identity and bank documents with an unverified recruiter.",
                ],
            },
            {
                category: "delivery",
                title: "Delivery and customs scams",
                how: "A message says a parcel is held because of an address issue, customs charge, or unpaid delivery fee. A link may collect payment or personal information.",
                warnings: [
                    "You are asked to pay a small unexpected fee to release a parcel.",
                    "The message does not identify a shipment you are expecting.",
                    "A link requests card details, sign-in details, or an OTP.",
                ],
                actions: [
                    "Check tracking only in the courier's official app or website.",
                    "Contact the seller or courier using contact details from its official site.",
                    "Do not install an app or pay through an unfamiliar link.",
                ],
            },
            {
                category: "payments",
                title: "UPI collect-request and refund scams",
                how: "A fraudster claims they need to send you money or refund a payment. They send a collect request and persuade you to enter your PIN or approve it.",
                warnings: [
                    "You are told to enter a UPI PIN to receive money.",
                    "An unexpected collect request appears in your UPI app.",
                    "A caller asks you to scan a QR code or approve a request for a refund.",
                ],
                actions: [
                    "Remember: a UPI PIN authorises a payment; it is not needed to receive money.",
                    "Reject unexpected collect requests and verify refunds in the official app.",
                    "Contact your bank or payment provider through its official channel.",
                ],
            },
            {
                category: "customer-care",
                title: "Fake customer-care numbers",
                how: "A fake support number is posted in a comment, search result, or social-media reply. The person who answers may ask for payment details or remote access.",
                warnings: [
                    "A number comes from an unsolicited message or an unverified comment.",
                    "Support asks for an OTP, UPI PIN, CVV, or screen-sharing access.",
                    "You are told to install an app from a link to receive help.",
                ],
                actions: [
                    "Find support details inside the official app or on the organisation's website.",
                    "Never share authentication codes or grant remote access to an unknown caller.",
                ],
            },
            {
                category: "loan-apps",
                title: "Loan-app harassment and extortion",
                how: "An unverified loan app may seek broad phone permissions and then threaten or shame borrowers and their contacts. Some messages demand extra money to stop the threats.",
                warnings: [
                    "A lender demands access to contacts, photos, or messages without a clear need.",
                    "Threats, abusive messages, or demands for unexplained extra fees.",
                    "A loan offer arrives through an unsolicited link or unknown app.",
                ],
                actions: [
                    "Check the lender and app through official financial-regulator or app-store information before applying.",
                    "Keep messages and payment records; contact your bank and local authorities if threatened.",
                    "Review app permissions and seek help from a trusted person.",
                ],
            },
            {
                category: "officials",
                title: "Impersonation and so-called digital-arrest calls",
                how: "A caller pretends to be police, a court, or another official and claims you are under investigation. They may demand secrecy, a video call, or an urgent transfer of money.",
                warnings: [
                    "A caller says you are under 'digital arrest' or must stay on a video call.",
                    "They threaten immediate arrest and tell you not to contact family or officials.",
                    "They demand money, bank access, or identity documents to 'clear' your name.",
                ],
                actions: [
                    "End the call; do not transfer money or share documents under pressure.",
                    "Verify independently using an official public contact number, not one the caller gives you.",
                    "Tell someone you trust and report threats to the appropriate authorities.",
                ],
            },
        ],
        safety: {
            title: "Do's and Don'ts",
            introduction: "Pause before acting on unexpected messages, calls, or payment requests.",
            dosTitle: "Do",
            dos: [
                "Verify requests using the organisation's official app or website that you open yourself.",
                "Call a known, official number to confirm an urgent request.",
                "Read payment and collect-request details carefully before approving anything.",
                "Ask someone you trust to review a suspicious message or call.",
            ],
            dontsTitle: "Don't",
            donts: [
                "Never share an OTP, password, UPI PIN, or CVV with another person.",
                "Do not click links in unexpected messages or reply with sensitive information.",
                "Do not install apps from unknown links or grant remote access to an unsolicited caller.",
                "Do not send money to claim a surprise prize, job, refund, or account release.",
            ],
        },
        response: {
            title: "If you have been scammed",
            introduction: "Act quickly. Contact your bank or payment provider immediately if money or account access may be at risk.",
            steps: [
                "Contact your bank or payment provider immediately and ask them to secure the account or payment method.",
                "Call the national cyber fraud helpline at 1930 as soon as possible.",
                "Report the incident at cybercrime.gov.in.",
                "Keep screenshots, phone numbers, messages, transaction IDs, and payment details.",
                "Change affected passwords and secure related accounts from a trusted device.",
            ],
            note: "Use official contact channels. Do not share passwords or OTPs with anyone offering to recover your money.",
        },
        quiz: {
            title: "Spot the scam",
            introduction: "For each example, choose Scam or Safe. Read the explanation before moving on.",
            scam: "Scam",
            safe: "Safe",
            correct: "That's right.",
            incorrect: "Not quite.",
            next: "Next example",
            finish: "See my score",
            restart: "Try again",
            questionCount: "Example {current} of {total}",
            finalTitle: "Quiz complete",
            finalScore: "Your score: {score} out of {total}",
            resultScam: "This example is a scam.",
            resultSafe: "This example is a safe message, but always verify unexpected requests.",
            questions: [
                {
                    message: "Your bank account will be blocked today. Update KYC now at this link.",
                    answer: "scam",
                    explanation: "This uses an urgent account threat and an unsolicited link. Check your account only in the official bank app or website.",
                },
                {
                    message: "Reached home safely. See you at dinner tonight!",
                    answer: "safe",
                    explanation: "This ordinary family message asks for no money, credentials, or action. Still be cautious if a familiar account makes an unusual request.",
                },
                {
                    message: "Tell me the OTP you just received so I can cancel the payment.",
                    answer: "scam",
                    explanation: "Never share an OTP. A legitimate person should not need you to read out a code to cancel a payment.",
                },
                {
                    message: "Card ending 1234: a purchase was made. If this was not you, check your bank app.",
                    answer: "safe",
                    explanation: "This is a neutral transaction alert that directs you to the official app, not an outside link. Do not use a phone number or link unless verified.",
                },
                {
                    message: "Pay a registration fee today to guarantee your work-from-home job.",
                    answer: "scam",
                    explanation: "A guaranteed job in exchange for an upfront fee is a warning sign. Verify openings on the employer's official careers page.",
                },
                {
                    message: "Police case against you. Stay on this video call and transfer money for verification.",
                    answer: "scam",
                    explanation: "Threats, secrecy, video-call pressure, and demands to transfer money are signs of impersonation. End the call and verify independently.",
                },
            ],
        },
    },
    hi: {
        eyebrow: "रुकें, जाँचें, पुष्टि करें",
        title: "संकेत पहचानें। सुरक्षित अगला कदम चुनें।",
        introduction: "धोखाधड़ी वाले संदेश और कॉल अक्सर जल्दबाज़ी, डर या लालच पैदा करते हैं। उदाहरण देखें, अनुरोध की अलग से पुष्टि करें और दबाव में संवेदनशील जानकारी कभी साझा न करें।",
        topicsTitle: "धोखाधड़ी के आम विषय",
        searchLabel: "धोखाधड़ी के विषय खोजें",
        searchPlaceholder: "विषय या चेतावनी संकेत खोजें",
        filtersLabel: "धोखाधड़ी के विषय फ़िल्टर करें",
        allTopics: "सभी विषय",
        noMatches: "आपकी खोज से कोई विषय नहीं मिला। दूसरा शब्द या फ़िल्टर आज़माएँ।",
        howItWorks: "यह कैसे काम करता है",
        warningSigns: "चेतावनी संकेत",
        whatToDo: "क्या करें",
        topics: [
            { id: "banking", label: "बैंक और KYC संदेश" },
            { id: "credentials", label: "OTP और UPI PIN की चोरी" },
            { id: "prizes", label: "लॉटरी और इनाम की धोखाधड़ी" },
            { id: "jobs", label: "नकली नौकरी के प्रस्ताव" },
            { id: "delivery", label: "डिलीवरी और कस्टम शुल्क की धोखाधड़ी" },
            { id: "payments", label: "UPI कलेक्ट और रिफंड की धोखाधड़ी" },
            { id: "customer-care", label: "नकली ग्राहक-सेवा नंबर" },
            { id: "loan-apps", label: "लोन ऐप से उत्पीड़न" },
            { id: "officials", label: "अधिकारी बनकर और 'डिजिटल अरेस्ट' कॉल" },
        ],
        cards: [
            {
                category: "banking",
                title: "नकली बैंक KYC या खाता बंद होने के संदेश",
                how: "संदेश में दावा होता है कि आपका बैंक खाता, कार्ड या KYC जल्द बंद हो जाएगा। आपसे संदेश के लिंक या उसमें दिए नंबर का उपयोग करने को कहा जाता है।",
                warnings: [
                    "खाता रोकने की धमकी के साथ अचानक समय-सीमा दी जाती है।",
                    "KYC अपडेट, साइन-इन या कार्ड जानकारी के लिए लिंक दिया जाता है।",
                    "OTP, PIN, पासवर्ड या दूर से फोन चलाने की अनुमति माँगी जाती है।",
                ],
                actions: [
                    "संदेश के लिंक या फोन नंबर का उपयोग न करें।",
                    "बैंक का आधिकारिक ऐप खोलें या उसकी जानी-पहचानी वेबसाइट खुद लिखें।",
                    "कार्ड पर छपे या आधिकारिक वेबसाइट पर दिए नंबर पर कॉल करें।",
                ],
            },
            {
                category: "credentials",
                title: "OTP और UPI PIN की चोरी",
                how: "कोई व्यक्ति भुगतान रद्द करने, रिफंड पाने या पहचान जाँचने के लिए OTP माँग सकता है। धोखेबाज़ पैसे भेजने के बहाने UPI कलेक्ट अनुरोध स्वीकार करवाकर PIN भी डलवा सकता है।",
                warnings: [
                    "कॉलर या संदेश आपसे OTP, PIN या CVV बताने को कहता है।",
                    "पैसे पाने के लिए UPI कलेक्ट अनुरोध स्वीकार करने को कहा जाता है।",
                    "स्क्रीन साझा करने या सहायता ऐप इंस्टॉल करने का दबाव होता है।",
                ],
                actions: [
                    "OTP, UPI PIN, पासवर्ड या CVV किसी के साथ साझा न करें।",
                    "UPI ऐप की स्क्रीन ध्यान से पढ़ें; कलेक्ट अनुरोध स्वीकार करने पर पैसे जा सकते हैं।",
                    "कॉल काटें और बैंक से आधिकारिक ऐप या ज्ञात नंबर से संपर्क करें।",
                ],
            },
            {
                category: "prizes",
                title: "लॉटरी और इनाम की धोखाधड़ी",
                how: "अनजान संदेश कहता है कि आपने लॉटरी, उपहार या इनाम जीता है। इनाम देने से पहले शुल्क, टैक्स या निजी जानकारी माँगी जाती है।",
                warnings: [
                    "ऐसी प्रतियोगिता जीतने का दावा किया जाता है जिसमें आपने भाग नहीं लिया।",
                    "इनाम लेने से पहले प्रोसेसिंग, टैक्स या डिलीवरी शुल्क माँगा जाता है।",
                    "बैंक जानकारी, OTP या लिंक पर क्लिक करने को कहा जाता है।",
                ],
                actions: [
                    "अचानक मिले इनाम के लिए पैसे न दें और निजी या बैंक जानकारी साझा न करें।",
                    "आयोजक की आधिकारिक वेबसाइट या संपर्क माध्यम से प्रस्ताव की जाँच करें।",
                ],
            },
            {
                category: "jobs",
                title: "रजिस्ट्रेशन शुल्क वाले नकली नौकरी प्रस्ताव",
                how: "भर्ती करने वाला नौकरी, अधिक कमाई या घर से आसान काम का वादा करता है। फिर रजिस्ट्रेशन, ट्रेनिंग, इंटरव्यू या उपकरण के नाम पर शुल्क माँगा जा सकता है।",
                warnings: [
                    "ठोस इंटरव्यू या कंपनी की जानकारी के बिना नौकरी दी जाती है।",
                    "पद, काम या इंटरव्यू पक्का करने के लिए पैसे माँगे जाते हैं।",
                    "भर्ती करने वाला निजी ईमेल इस्तेमाल करता है या जल्दी निर्णय का दबाव देता है।",
                ],
                actions: [
                    "कंपनी के आधिकारिक करियर पेज पर नौकरी की पुष्टि करें।",
                    "पहले से शुल्क न दें और अपुष्ट व्यक्ति को पहचान या बैंक दस्तावेज़ न भेजें।",
                ],
            },
            {
                category: "delivery",
                title: "डिलीवरी और कस्टम शुल्क की धोखाधड़ी",
                how: "संदेश कहता है कि पता गलत है, पार्सल कस्टम में रुका है या डिलीवरी शुल्क बाकी है। लिंक से भुगतान या निजी जानकारी ली जा सकती है।",
                warnings: [
                    "पार्सल छुड़ाने के लिए अचानक छोटा-सा शुल्क माँगा जाता है।",
                    "संदेश में उस पार्सल की जानकारी नहीं होती जिसका आप इंतज़ार कर रहे हैं।",
                    "लिंक कार्ड, साइन-इन जानकारी या OTP माँगता है।",
                ],
                actions: [
                    "ट्रैकिंग केवल कूरियर के आधिकारिक ऐप या वेबसाइट पर देखें।",
                    "विक्रेता या कूरियर से आधिकारिक वेबसाइट पर दिए संपर्क माध्यम से बात करें।",
                    "अनजान लिंक से ऐप इंस्टॉल न करें और भुगतान न करें।",
                ],
            },
            {
                category: "payments",
                title: "UPI कलेक्ट अनुरोध और रिफंड की धोखाधड़ी",
                how: "धोखेबाज़ कहता है कि वह पैसे भेजेगा या भुगतान लौटाएगा। फिर वह कलेक्ट अनुरोध भेजकर आपसे PIN डालने या उसे मंज़ूर करने को कहता है।",
                warnings: [
                    "पैसे पाने के लिए UPI PIN डालने को कहा जाता है।",
                    "UPI ऐप में अनजान कलेक्ट अनुरोध दिखाई देता है।",
                    "रिफंड के लिए QR कोड स्कैन या अनुरोध स्वीकार करने को कहा जाता है।",
                ],
                actions: [
                    "UPI PIN से भुगतान की अनुमति मिलती है; पैसे पाने के लिए इसकी ज़रूरत नहीं होती।",
                    "अनजान कलेक्ट अनुरोध अस्वीकार करें और रिफंड आधिकारिक ऐप में जाँचें।",
                    "बैंक या भुगतान सेवा से उसके आधिकारिक माध्यम से संपर्क करें।",
                ],
            },
            {
                category: "customer-care",
                title: "नकली ग्राहक-सेवा नंबर",
                how: "नकली सहायता नंबर किसी टिप्पणी, खोज परिणाम या सोशल-मीडिया जवाब में दिया जाता है। जवाब देने वाला व्यक्ति भुगतान जानकारी या फोन तक दूरस्थ पहुँच माँग सकता है।",
                warnings: [
                    "नंबर अनचाहे संदेश या अपुष्ट टिप्पणी से मिला है।",
                    "सहायता के नाम पर OTP, UPI PIN, CVV या स्क्रीन साझा करने को कहा जाता है।",
                    "मदद के लिए लिंक से ऐप इंस्टॉल करने को कहा जाता है।",
                ],
                actions: [
                    "सहायता नंबर आधिकारिक ऐप या संस्था की वेबसाइट से खोजें।",
                    "अनजान कॉलर को सुरक्षा कोड न बताएँ और दूरस्थ पहुँच न दें।",
                ],
            },
            {
                category: "loan-apps",
                title: "लोन ऐप से उत्पीड़न और वसूली",
                how: "अपुष्ट लोन ऐप फोन के संपर्कों और तस्वीरों की अनावश्यक अनुमति माँग सकता है। बाद में उधार लेने वाले और उनके परिचितों को धमकाया या बदनाम किया जा सकता है।",
                warnings: [
                    "ऋणदाता बिना स्पष्ट कारण संपर्क, तस्वीर या संदेश देखने की अनुमति माँगता है।",
                    "धमकी, गाली-गलौज या बिना कारण अतिरिक्त शुल्क की माँग होती है।",
                    "लोन का प्रस्ताव अनचाहे लिंक या अनजान ऐप से आता है।",
                ],
                actions: [
                    "आवेदन से पहले आधिकारिक नियामक या ऐप-स्टोर जानकारी से ऋणदाता जाँचें।",
                    "धमकी मिलने पर संदेश और भुगतान रिकॉर्ड रखें तथा बैंक और स्थानीय अधिकारियों से संपर्क करें।",
                    "ऐप की अनुमतियाँ जाँचें और किसी भरोसेमंद व्यक्ति से मदद लें।",
                ],
            },
            {
                category: "officials",
                title: "अधिकारी बनकर और तथाकथित 'डिजिटल अरेस्ट' कॉल",
                how: "कॉलर पुलिस, अदालत या किसी अधिकारी का नाम लेकर कहता है कि आपके खिलाफ जाँच चल रही है। वह गोपनीयता, वीडियो कॉल या तुरंत पैसे भेजने का दबाव बना सकता है।",
                warnings: [
                    "कॉलर कहता है कि आपको 'डिजिटल अरेस्ट' किया गया है या वीडियो कॉल पर रहना होगा।",
                    "तुरंत गिरफ्तारी की धमकी देकर परिवार या अधिकारियों से बात करने से रोका जाता है।",
                    "नाम साफ़ करने के लिए पैसे, बैंक पहुँच या पहचान दस्तावेज़ माँगे जाते हैं।",
                ],
                actions: [
                    "कॉल काटें; दबाव में पैसे न भेजें और दस्तावेज़ साझा न करें।",
                    "कॉलर के दिए नंबर से नहीं, बल्कि आधिकारिक सार्वजनिक नंबर से खुद पुष्टि करें।",
                    "किसी भरोसेमंद व्यक्ति को बताएँ और धमकी की शिकायत संबंधित अधिकारियों से करें।",
                ],
            },
        ],
        safety: {
            title: "क्या करें और क्या न करें",
            introduction: "अनजान संदेश, कॉल या भुगतान अनुरोध पर कार्रवाई करने से पहले रुकें।",
            dosTitle: "क्या करें",
            dos: [
                "संस्था का आधिकारिक ऐप खोलकर या वेबसाइट खुद लिखकर अनुरोध की पुष्टि करें।",
                "जल्दी कार्रवाई वाले अनुरोध की पुष्टि किसी ज्ञात आधिकारिक नंबर पर कॉल करके करें।",
                "भुगतान मंज़ूर करने से पहले UPI स्क्रीन और कलेक्ट अनुरोध का विवरण पढ़ें।",
                "संदिग्ध संदेश या कॉल किसी भरोसेमंद व्यक्ति को दिखाएँ।",
            ],
            dontsTitle: "क्या न करें",
            donts: [
                "OTP, पासवर्ड, UPI PIN या CVV कभी किसी दूसरे व्यक्ति को न बताएँ।",
                "अनचाहे संदेश के लिंक न खोलें और निजी जानकारी भेजकर जवाब न दें।",
                "अनजान लिंक से ऐप इंस्टॉल न करें और अनचाहे कॉलर को दूर से फोन चलाने की अनुमति न दें।",
                "अचानक मिले इनाम, नौकरी, रिफंड या खाता खुलवाने के लिए पैसे न भेजें।",
            ],
        },
        response: {
            title: "यदि आपके साथ धोखाधड़ी हुई है",
            introduction: "जल्दी कदम उठाएँ। पैसे या खाते को खतरा हो तो तुरंत अपने बैंक या भुगतान सेवा से संपर्क करें।",
            steps: [
                "अपने बैंक या भुगतान सेवा से तुरंत संपर्क करें और खाते या भुगतान माध्यम को सुरक्षित करने को कहें।",
                "राष्ट्रीय साइबर धोखाधड़ी हेल्पलाइन 1930 पर जल्द से जल्द कॉल करें।",
                "घटना की रिपोर्ट cybercrime.gov.in पर करें।",
                "स्क्रीनशॉट, फोन नंबर, संदेश, लेन-देन आईडी और भुगतान की जानकारी सुरक्षित रखें।",
                "भरोसेमंद डिवाइस से प्रभावित पासवर्ड बदलें और संबंधित खातों को सुरक्षित करें।",
            ],
            note: "आधिकारिक संपर्क माध्यम अपनाएँ। पैसे वापस दिलाने का दावा करने वाले किसी व्यक्ति को पासवर्ड या OTP न दें।",
        },
        quiz: {
            title: "धोखाधड़ी पहचानें",
            introduction: "हर उदाहरण के लिए 'धोखाधड़ी' या 'सुरक्षित' चुनें। आगे बढ़ने से पहले कारण पढ़ें।",
            scam: "धोखाधड़ी",
            safe: "सुरक्षित",
            correct: "सही जवाब।",
            incorrect: "यह सही जवाब नहीं है।",
            next: "अगला उदाहरण",
            finish: "मेरा स्कोर देखें",
            restart: "फिर से कोशिश करें",
            questionCount: "उदाहरण {current} / {total}",
            finalTitle: "क्विज़ पूरा हुआ",
            finalScore: "आपका स्कोर: {total} में से {score}",
            resultScam: "यह उदाहरण धोखाधड़ी है।",
            resultSafe: "यह सुरक्षित संदेश है, फिर भी अनपेक्षित अनुरोधों की पुष्टि करें।",
            questions: [
                {
                    message: "आज आपका बैंक खाता बंद होगा। इस लिंक पर अभी KYC अपडेट करें।",
                    answer: "scam",
                    explanation: "इसमें खाते की धमकी और अनचाहा लिंक है। खाता केवल बैंक के आधिकारिक ऐप या वेबसाइट में जाँचें।",
                },
                {
                    message: "घर सुरक्षित पहुँच गया/गई। आज रात खाने पर मिलते हैं!",
                    answer: "safe",
                    explanation: "यह सामान्य पारिवारिक संदेश है और इसमें पैसे, पासवर्ड या कार्रवाई नहीं माँगी गई। फिर भी परिचित खाते से आए असामान्य अनुरोध की पुष्टि करें।",
                },
                {
                    message: "भुगतान रद्द करने के लिए अभी आया OTP मुझे बताइए।",
                    answer: "scam",
                    explanation: "OTP कभी साझा न करें। भुगतान रद्द करने के लिए किसी भरोसेमंद व्यक्ति को आपका कोड जानने की ज़रूरत नहीं होती।",
                },
                {
                    message: "कार्ड के आखिरी अंक 1234: खरीदारी हुई। अगर यह आपने नहीं की, तो बैंक ऐप देखें।",
                    answer: "safe",
                    explanation: "यह सामान्य लेन-देन सूचना है और बाहरी लिंक के बजाय आधिकारिक ऐप देखने को कहती है। किसी अनजान नंबर या लिंक का उपयोग न करें।",
                },
                {
                    message: "घर से काम की नौकरी पक्की करने के लिए आज रजिस्ट्रेशन शुल्क भेजें।",
                    answer: "scam",
                    explanation: "पहले शुल्क के बदले पक्की नौकरी देने का दावा चेतावनी संकेत है। कंपनी के आधिकारिक करियर पेज पर नौकरी जाँचें।",
                },
                {
                    message: "आपके खिलाफ पुलिस केस है। वीडियो कॉल पर रहें और जाँच के लिए पैसे भेजें।",
                    answer: "scam",
                    explanation: "धमकी, गोपनीयता, वीडियो कॉल का दबाव और पैसे माँगना अधिकारी बनकर की जाने वाली धोखाधड़ी के संकेत हैं। कॉल काटें और अलग से पुष्टि करें।",
                },
            ],
        },
    },
};

const awarenessPage = document.getElementById("scam-awareness-page");

if (awarenessPage) {
    let activeTopic = "all";
    let searchQuery = "";
    let quizIndex = 0;
    let quizScore = 0;
    let selectedAnswer = null;

    function currentContent() {
        return awarenessContent[window.getCurrentLanguage()] || awarenessContent.en;
    }

    function createElement(tagName, className, text) {
        const element = document.createElement(tagName);
        if (className) {
            element.className = className;
        }
        if (text !== undefined) {
            element.textContent = text;
        }
        return element;
    }

    function appendList(parent, values, className) {
        const list = createElement("ul", className);
        values.forEach((value) => list.appendChild(createElement("li", "", value)));
        parent.appendChild(list);
    }

    function renderTopicCards(content) {
        const cardsContainer = document.getElementById("awareness-cards");
        const noMatches = document.getElementById("awareness-no-matches");
        cardsContainer.replaceChildren();

        const cards = content.cards.filter((card) => {
            const matchesTopic = activeTopic === "all" || card.category === activeTopic;
            const searchableText = [
                card.title,
                card.how,
                ...card.warnings,
                ...card.actions,
            ].join(" ").toLocaleLowerCase();
            return matchesTopic && searchableText.includes(searchQuery);
        });

        cards.forEach((card) => {
            const article = createElement("article", "panel awareness-topic-card");
            const heading = createElement("h2", "", card.title);
            article.appendChild(heading);

            const howSection = createElement("section", "awareness-topic-section");
            howSection.appendChild(createElement("h3", "", content.howItWorks));
            howSection.appendChild(createElement("p", "", card.how));
            article.appendChild(howSection);

            const warningSection = createElement("section", "awareness-topic-section");
            warningSection.appendChild(createElement("h3", "", content.warningSigns));
            appendList(warningSection, card.warnings, "awareness-warning-list");
            article.appendChild(warningSection);

            const actionSection = createElement("section", "awareness-topic-section");
            actionSection.appendChild(createElement("h3", "", content.whatToDo));
            appendList(actionSection, card.actions, "awareness-action-list");
            article.appendChild(actionSection);
            cardsContainer.appendChild(article);
        });

        noMatches.hidden = cards.length > 0;
    }

    function renderFilters(content) {
        const filterGroup = document.getElementById("awareness-filters");
        filterGroup.replaceChildren();
        const filters = [{ id: "all", label: content.allTopics }, ...content.topics];

        filters.forEach((filter) => {
            const button = createElement(
                "button",
                "awareness-filter-chip",
                filter.label
            );
            button.type = "button";
            button.setAttribute("aria-pressed", String(activeTopic === filter.id));
            button.addEventListener("click", () => {
                activeTopic = filter.id;
                renderPage();
            });
            filterGroup.appendChild(button);
        });
    }

    function renderQuiz(content) {
        const container = document.getElementById("awareness-quiz");
        const quiz = content.quiz;
        container.replaceChildren();
        const title = createElement("h2", "", quiz.title);
        title.tabIndex = -1;
        container.appendChild(title);
        container.appendChild(createElement("p", "awareness-quiz-intro", quiz.introduction));

        if (quizIndex >= quiz.questions.length) {
            const complete = createElement("div", "awareness-quiz-result");
            complete.setAttribute("role", "status");
            const resultTitle = createElement("h3", "", quiz.finalTitle);
            resultTitle.tabIndex = -1;
            complete.appendChild(resultTitle);
            complete.appendChild(createElement(
                "p",
                "",
                quiz.finalScore
                    .replace("{score}", String(quizScore))
                    .replace("{total}", String(quiz.questions.length))
            ));
            const restart = createElement("button", "button button-outline", quiz.restart);
            restart.type = "button";
            restart.addEventListener("click", () => {
                quizIndex = 0;
                quizScore = 0;
                selectedAnswer = null;
                renderQuiz(currentContent());
                const firstChoice = container.querySelector(".awareness-quiz-choices button");
                if (firstChoice) {
                    firstChoice.focus();
                }
            });
            complete.appendChild(restart);
            container.appendChild(complete);
            return;
        }

        const question = quiz.questions[quizIndex];
        container.appendChild(createElement(
            "p",
            "awareness-quiz-progress",
            quiz.questionCount
                .replace("{current}", String(quizIndex + 1))
                .replace("{total}", String(quiz.questions.length))
        ));
        container.appendChild(createElement("blockquote", "awareness-quiz-message", question.message));

        const choices = createElement("div", "awareness-quiz-choices");
        [
            { value: "scam", label: quiz.scam },
            { value: "safe", label: quiz.safe },
        ].forEach((choice) => {
            const button = createElement("button", "button button-outline", choice.label);
            button.type = "button";
            button.disabled = selectedAnswer !== null;
            button.addEventListener("click", () => {
                selectedAnswer = choice.value;
                if (selectedAnswer === question.answer) {
                    quizScore += 1;
                }
                renderQuiz(currentContent());
                const feedback = container.querySelector(".awareness-quiz-feedback");
                if (feedback) {
                    feedback.focus();
                }
            });
            choices.appendChild(button);
        });
        container.appendChild(choices);

        if (selectedAnswer !== null) {
            const correct = selectedAnswer === question.answer;
            const feedback = createElement(
                "div",
                "awareness-quiz-feedback " + (correct ? "is-correct" : "is-incorrect")
            );
            feedback.tabIndex = -1;
            feedback.setAttribute("role", "status");
            feedback.appendChild(createElement(
                "strong",
                "",
                (correct ? quiz.correct : quiz.incorrect) + " " +
                    (question.answer === "scam" ? quiz.resultScam : quiz.resultSafe)
            ));
            feedback.appendChild(createElement("p", "", question.explanation));
            container.appendChild(feedback);

            const next = createElement(
                "button",
                "button button-primary",
                quizIndex === quiz.questions.length - 1 ? quiz.finish : quiz.next
            );
            next.type = "button";
            next.addEventListener("click", () => {
                quizIndex += 1;
                selectedAnswer = null;
                renderQuiz(currentContent());
                const nextProgress = container.querySelector(".awareness-quiz-progress");
                if (nextProgress) {
                    nextProgress.focus();
                } else {
                    const finalHeading = container.querySelector(".awareness-quiz-result h3");
                    if (finalHeading) {
                        finalHeading.focus();
                    }
                }
            });
            container.appendChild(next);
        }
    }

    function renderPage() {
        const content = currentContent();
        awarenessPage.replaceChildren();

        const intro = createElement("header", "page-intro awareness-page-intro");
        intro.appendChild(createElement("p", "eyebrow", content.eyebrow));
        intro.appendChild(createElement("h1", "", content.title));
        intro.appendChild(createElement("p", "", content.introduction));
        awarenessPage.appendChild(intro);

        const topicsSection = createElement("section", "awareness-section");
        topicsSection.appendChild(createElement("h2", "awareness-section-title", content.topicsTitle));
        const searchLabel = createElement("label", "awareness-search-label", content.searchLabel);
        searchLabel.htmlFor = "awareness-search";
        const search = createElement("input", "awareness-search");
        search.id = "awareness-search";
        search.type = "search";
        search.placeholder = content.searchPlaceholder;
        search.value = searchQuery;
        search.autocomplete = "off";
        search.addEventListener("input", () => {
            searchQuery = search.value.trim().toLocaleLowerCase();
            renderTopicCards(currentContent());
        });
        const filterHeading = createElement("h3", "awareness-filter-heading", content.filtersLabel);
        const filterGroup = createElement("div", "awareness-filter-list");
        filterGroup.id = "awareness-filters";
        filterGroup.setAttribute("role", "group");
        filterGroup.setAttribute("aria-label", content.filtersLabel);
        const cardsContainer = createElement("div", "awareness-card-grid");
        cardsContainer.id = "awareness-cards";
        const noMatches = createElement("p", "notice notice-info awareness-no-matches", content.noMatches);
        noMatches.id = "awareness-no-matches";
        noMatches.hidden = true;
        noMatches.setAttribute("role", "status");
        topicsSection.append(searchLabel, search, filterHeading, filterGroup, cardsContainer, noMatches);
        awarenessPage.appendChild(topicsSection);

        const safetySection = createElement("section", "panel awareness-guidance");
        safetySection.appendChild(createElement("h2", "", content.safety.title));
        safetySection.appendChild(createElement("p", "awareness-section-intro", content.safety.introduction));
        const safetyColumns = createElement("div", "awareness-safety-columns");
        const dos = createElement("section", "awareness-safety-card is-do");
        dos.appendChild(createElement("h3", "", content.safety.dosTitle));
        appendList(dos, content.safety.dos, "awareness-action-list");
        const donts = createElement("section", "awareness-safety-card is-dont");
        donts.appendChild(createElement("h3", "", content.safety.dontsTitle));
        appendList(donts, content.safety.donts, "awareness-warning-list");
        safetyColumns.append(dos, donts);
        safetySection.appendChild(safetyColumns);
        awarenessPage.appendChild(safetySection);

        const responseSection = createElement("section", "panel awareness-response");
        responseSection.appendChild(createElement("h2", "", content.response.title));
        responseSection.appendChild(createElement("p", "awareness-section-intro", content.response.introduction));
        const steps = createElement("ol", "awareness-response-steps");
        content.response.steps.forEach((step) => steps.appendChild(createElement("li", "", step)));
        responseSection.appendChild(steps);
        responseSection.appendChild(createElement("p", "notice notice-warning awareness-response-note", content.response.note));
        awarenessPage.appendChild(responseSection);

        const quizSection = createElement("section", "panel awareness-quiz");
        quizSection.id = "awareness-quiz";
        awarenessPage.appendChild(quizSection);

        renderFilters(content);
        renderTopicCards(content);
        renderQuiz(content);
    }

    window.addEventListener("spamshield:languagechange", renderPage);
    renderPage();
}
