"""Disjoint synthetic name, place, clinical, and canary pools for TRAIN and HELD-OUT-SHIFT splits.

All names and identifiers here are synthetic and constructed to remain disjoint from
the practice dataset (kit/dev/truth/truth.json) as well as across TRAIN and HELD-OUT-SHIFT.
"""
from __future__ import annotations

# Disjoint given-name + surname pools (Latin, Devanagari, regional, common-word, drug-like)
# Format: (latin_first, deva_first, latin_last, deva_last, gender, region_tag)
TRAIN_PEOPLE_POOL: list[tuple[str, str, str, str, str, str]] = [
    ("Girish", "गिरीश", "Chaturvedi", "चतुर्वेदी", "M", "hindi_belt"),
    ("Nirmala", "निर्मला", "Dubey", "दुबे", "F", "hindi_belt"),
    ("Pradeep", "प्रदीप", "Tripathi", "त्रिपाठी", "M", "hindi_belt"),
    ("Suman", "सुमन", "Saxena", "सक्सेना", "F", "hindi_belt"),
    ("Prabhat", "प्रभात", "Chatterjee", "चटर्जी", "M", "bengali"),
    ("Ananya", "अनन्या", "Banerjee", "बनर्जी", "F", "bengali"),
    ("Debashish", "देबाशीष", "Sen", "सेन", "M", "bengali"),
    ("Karthik", "कार्तिक", "Subramanian", "सुब्रमण्यन", "M", "tamil"),
    ("Meenakshi", "मीनाक्षी", "Sundaram", "सुंदरम", "F", "tamil"),
    ("Srinivas", "श्रीनिवास", "Rao", "राव", "M", "telugu"),
    ("Padma", "पद्मा", "Reddy", "रेड्डी", "F", "telugu"),
    ("Harikrishnan", "हरिकृष्णन", "Nair", "नायर", "M", "malayalam"),
    ("Lakshmi", "लक्ष्मी", "Menon", "मेनन", "F", "malayalam"),
    ("Milind", "मिलिंद", "Deshmukh", "देशमुख", "M", "marathi"),
    ("Vaishali", "वैशाली", "Kulkarni", "कुलकर्णी", "F", "marathi"),
    ("Gurpreet", "गुरप्रीत", "Gill", "गिल", "M", "punjabi_sikh"),
    ("Harleen", "हरलीन", "Bedi", "बेदी", "F", "punjabi_sikh"),
    ("Bhavesh", "भावेश", "Desai", "देसाई", "M", "gujarati"),
    ("Hetal", "हेतल", "Mehta", "मेहता", "F", "gujarati"),
    ("Tariq", "तारिक", "Chishti", "चिश्ती", "M", "muslim"),
    ("Shagufta", "शगुफ्ता", "Begum", "बेगम", "F", "muslim"),
    ("Nadeem", "नदीम", "Mirza", "मिर्ज़ा", "M", "muslim"),
    ("Thomas", "थॉमस", "Varghese", "वर्गीस", "M", "christian"),
    ("Rosy", "रोजी", "Fernandes", "फर्नांडीस", "F", "christian"),
    # Common-word / drug-like / single-token / rare-long traps
    ("Kiran", "किरण", "Bisht", "बिष्ट", "F", "common_word"),
    ("Sunder", "सुंदर", "Rawat", "रावत", "M", "common_word"),
    ("Pushpa", "पुष्पा", "Jha", "झा", "F", "common_word"),
    ("Manju", "मंजू", "Bhatt", "भट्ट", "F", "common_word"),
    ("Rose", "रोज़", "D'Souza", "डिसूजा", "F", "common_word"),
    ("Alok", "आलोक", "Dolo", "डोलो", "M", "drug_trap"),
]

HELDOUT_PEOPLE_POOL: list[tuple[str, str, str, str, str, str]] = [
    ("Bhubaneshwar", "भुवनेश्वर", "Upadhyay", "उपाध्याय", "M", "hindi_belt"),
    ("Kalpana", "कल्पना", "Agnihotri", "अग्निहोत्री", "F", "hindi_belt"),
    ("Prasenjit", "प्रसेनजीत", "Mukherjee", "मुखर्जी", "M", "bengali"),
    ("Rituparna", "ऋतुपर्णा", "Bose", "बोस", "F", "bengali"),
    ("Senthil", "सेंथिल", "Natarajan", "नटराजन", "M", "tamil"),
    ("Tamilselvi", "तमिलसेल्वी", "Arumugam", "अरुमुगम", "F", "tamil"),
    ("Venkatesh", "वेंकटेश", "Naidu", "नायडू", "M", "telugu"),
    ("Satyavati", "सत्यवती", "Gowda", "गौड़ा", "F", "telugu"),
    ("Unnikrishnan", "उन्नीकृष्णन", "Pillai", "पिल्लई", "M", "malayalam"),
    ("Sreelatha", "श्रीलता", "Warrier", "वारियर", "F", "malayalam"),
    ("Shrikant", "श्रीकांत", "Joshi", "जोशी", "M", "marathi"),
    ("Ashwini", "अश्विनी", "Patwardhan", "पटवर्धन", "F", "marathi"),
    ("Balwinder", "बलविंदर", "Sandhu", "संधू", "M", "punjabi_sikh"),
    ("Navjot", "नवजोत", "Sidhu", "सिद्धू", "F", "punjabi_sikh"),
    ("Jignesh", "जिग्नेश", "Parikh", "पारीख", "M", "gujarati"),
    ("Nirali", "निराली", "Zaveri", "ज़वेरी", "F", "gujarati"),
    ("Farhan", "फरहान", "Kazmi", "काज़मी", "M", "muslim"),
    ("Humaira", "हुमैरा", "Nizam", "निज़ाम", "F", "muslim"),
    ("Arif", "आरिफ़", "Mansoor", "मंसूर", "M", "muslim"),
    ("Mathew", "मैथ्यू", "Kurien", "कुरियन", "M", "christian"),
    ("Beena", "बीना", "Rodrigues", "रोड्रिग्स", "F", "christian"),
    ("Chandan", "चंदन", "Garg", "गर्ग", "M", "common_word"),
    ("Daya", "दया", "Narang", "नारंग", "F", "common_word"),
    ("Asprin", "एस्प्रिन", "Khosla", "खोसला", "M", "drug_trap"),
    ("Devendra", "देवेंद्र", "Solanki", "सोलांकी", "M", "hindi_belt"),
    ("Meera", "मीरा", "Solanki", "सोलांकी", "F", "hindi_belt"),
    ("Thiruvengadam", "थिरुवेंगडम", "Krishnamurthy", "कृष्णमूर्ति", "M", "rare_long"),
    ("Chandrakanta", "चंद्रकांता", "Bhattacharjee", "भट्टाचार्जी", "F", "rare_long"),
]

# High-entropy synthetic canaries (completely disjoint from people pools & dev/truth)
TRAIN_CANARIES: list[tuple[str, str, str, str]] = [
    ("Zephaniah", "ज़ेफ़नियाह", "Kandathil", "कंदथिल"),
    ("Vindhyachal", "विंध्याचल", "Pudukkottai", "पुदुक्कोट्टई"),
    ("Qutubuddin", "कुतुबुद्दीन", "Channapatna", "चन्नपटना"),
    ("Nandikeshwar", "नंदिकेश्वर", "Kottarakkara", "कोट्टाराक्कारा"),
]

HELDOUT_CANARIES: list[tuple[str, str, str, str]] = [
    ("Xylander", "ज़ाइलैंडर", "Thoothukudi", "तूतुकुडी"),
    ("Bhadreshwar", "भद्रेश्वर", "Kunnamkulam", "कुन्नमकुलम"),
    ("Shajaruddin", "शजरुद्दीन", "Srikalahasti", "श्रीकालहस्ती"),
    ("Yagnavalkya", "याज्ञवल्क्य", "Bhadrachalam", "भद्राचलम"),
]

# Synthetic districts / tehsils / villages / mohallas / landmarks
PLACES_TRAIN: list[tuple[str, str, str, str, str]] = [
    # (district, tehsil, village_latin, village_deva, pin_prefix)
    ("Etawah", "Saifai", "Nagla Karan", "नगला करण", "206"),
    ("Jhansi", "Mauranipur", "Bamor Bujurg", "बामौर बुजुर्ग", "284"),
    ("Gorakhpur", "Sahjanwa", "Piprauli", "पिपरौली", "273"),
    ("Varanasi", "Pindra", "Karkhiyaon", "करखियांव", "221"),
]

PLACES_HELDOUT: list[tuple[str, str, str, str, str]] = [
    ("Aligarh", "Khair", "Jattari", "जट्टारी", "202"),
    ("Meerut", "Sardhana", "Kaili", "कैली", "250"),
    ("Bareilly", "Aonla", "Ramnagar", "रामनगर", "243"),
    ("Prayagraj", "Phulpur", "Sahson", "सहसों", "212"),
]

MOHALLAS = ["Shastri Nagar", "Katra Bazaar", "Civil Lines", "Naya Ganj", "Indira Colony"]
LANDMARKS = ["near Water Tank", "opp Primary School", "near Railway Crossing", "behind Post Office"]

# Clinical vocabularies for preserve probes and meaning traps
MEDICATIONS = [
    ("Paracetamol", "650 mg", "1-1-1", "5 days"),
    ("Ramipril", "5 mg", "1-0-0", "30 days"),
    ("Pan-D", "40 mg", "1-0-0", "14 days"),
    ("Amlodipine", "5 mg", "0-0-1", "30 days"),
    ("Inj Insulin", "10 IU", "1-0-1", "7 days"),
    ("Ceftriaxone", "1 g", "BD", "5 days"),
]

DIAGNOSES = [
    ("A90", "Dengue fever", False),
    ("I10", "Essential (primary) hypertension", False),
    ("E11.9", "Type 2 diabetes mellitus without complications", False),
    ("G20", "Parkinson's disease", False),
    ("K50.9", "Crohn's disease, unspecified", False),
    ("B55.0", "Visceral leishmaniasis (kala-azar)", True),  # rare
    ("A82.9", "Rabies, unspecified", True),  # rare
    ("G61.0", "Guillain-Barre syndrome", True),  # rare
]

DOCTORS = [
    ("Dr. Avinash Kulkarni", "MD Medicine"),
    ("Dr. Nandini Iyer", "MS Surgery"),
    ("Dr. Girish Bhandari", "MD Pediatrics"),
]

LAB_TESTS = [
    ("Haemoglobin", "718-7", "g/dL", "12.0-16.0", "11.2"),
    ("Random Blood Sugar", "2339-0", "mg/dL", "70-140", "184"),
    ("Serum Creatinine", "2160-0", "mg/dL", "0.6-1.2", "1.4"),
    ("Platelet Count", "777-3", "/uL", "150000-450000", "42000"),
]

HOSPITALS_TRAIN = [
    ("Nirmal Care Hospital", "NRM"),
    ("Janata Seva Kendra", "JSK"),
    ("Surya Trust Clinic", "STC"),
    ("District Hospital Etawah", "DHE"),
]

HOSPITALS_HELDOUT = [
    ("Kaveri Medical Centre", "KMC"),
    ("Arogya Niketan Trust", "ANT"),
    ("Prabhat Polyclinic", "PPC"),
    ("District Hospital Aligarh", "DHA"),
]
