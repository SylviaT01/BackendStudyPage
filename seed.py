from app import db, app
from models import User, Expert, Service, ProjectRequest, ProjectType, Subject
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

def seed_database():
    # Create some users
    user1 = User(
        username='john_doe',
        email='john@example.com',
        phone_number='123-456-7890',
        is_admin=False
    )
    user1.set_password('password123')

    admin1 = User(
        username='bett',
        email='admin@example.com',
        phone_number='987-654-3210',
        is_admin=True
    )
    admin1.set_password('admin_password')

    # Create project types
    project_types = [
        ProjectType(name='Annotated Bibliography'),
        ProjectType(name='Application Essay'),
        ProjectType(name='Article'),
        ProjectType(name='Business Plan'),
        ProjectType(name='Capstone project'),
        ProjectType(name='Case Study'),
        ProjectType(name='Code'),
        ProjectType(name='Content Writing'),
        ProjectType(name='Coursework'),
        ProjectType(name='Creative Writing'),
        ProjectType(name='Dissertation'),
        ProjectType(name='Editing'),
        ProjectType(name='Essay'),
        ProjectType(name='Excel assignment'),
        ProjectType(name='Math solving'),
        ProjectType(name='Other types'),
        ProjectType(name='Outline'),
        ProjectType(name='Personal Statement'),
        ProjectType(name='Presentation'),
        ProjectType(name='Proposal'),
    ]

    # Define subjects
    subjects = [
    "Accounting",
    "Algebra",
    "Anatomy",
    "Anthropology",
    "Architecture",
    "Art",
    "Biochemistry",
    "Biology",
    "Business",
    "Chemistry",
    "Communications",
    "Creative Writing",
    "Criminal Justice",
    "Cultural Studies",
    "Economics",
    "Education",
    "Engineering",
    "English",
    "Environmental Science",
    "Finance",
    "Geography",
    "History",
    "Information Technology",
    "International Relations",
    "Law",
    "Literature",
    "Mathematics",
    "Nursing",
    "Philosophy",
    "Physics",
    "Political Science",
    "Psychology",
    "Public Administration",
    "Sociology",
    "Statistics",
    "Theology",
    "Web Development"
]
    # Seed subjects into the database
    for subject_name in subjects:
        subject = Subject(name=subject_name)
        db.session.add(subject)

    # Create some experts
    expert1 = Expert(
        title='Academic Writer',
        name='Jane Smith',
        expertise='Essay Writing, Research Papers, Admissions Essays',
        description='Experienced academic writer specializing in essays and research papers.',
        biography='Jane has been helping students with academic writing for over 8 years.',
        education='PhD in Literature',
        languages='English, French',
        project_type=project_types[0],  # Linking expert to the first project type
        profile_picture='https://example.com/picture1.jpg'
    )

    expert2 = Expert(
        name='Mike Johnson',
        title='Technical Writer',
        expertise='Reports, Presentations, Case Studies',
        description='Technical writer focused on case studies, lab reports, and presentations.',
        biography='Mike has a background in engineering and technical documentation.',
        education='MS in Engineering',
        languages='English, Spanish',
        project_type=project_types[1],  # Linking expert to the second project type
        profile_picture='https://example.com/picture2.jpg'
    )

    services = [
    Service(
        title='Essays',
        description='cool proj',
        base_price=5.00,
        price_per_page=10.00,
        unit='per page',
        project_type_id=1,  # Ensure you reference the ID, not the object itself
        subject_id=1
    ),
    Service(
        title='Admissions Essay',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=2, 
        subject_id=2
    ),
        Service(
        title='PowerPoint Presentation',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=3, 
        subject_id=2
    ),
        Service(
        title='Research Paper',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=4, 
        subject_id=2
    ),
        Service(
        title='Assignments',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=5, 
        subject_id=2
    ),
        Service(
        title='Homework',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=6, 
        subject_id=2
    ),
        Service(
        title='Speech',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=7, 
        subject_id=2
    ),
        Service(
        title='Book Reviews',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=8, 
        subject_id=2
    ),
        Service(
        title='Coursework',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=9, 
        subject_id=2
    ),
        Service(
        title='Personal Statement',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=10, 
        subject_id=2
    ),
        Service(
        title='PhD Dissertation',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=11, 
        subject_id=2
    ),
        Service(
        title='Thesis',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=12, 
        subject_id=2
    ),
        Service(
        title='Case Study',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=13, 
        subject_id=2
    ),
        Service(
        title='Term Paper',
        description='cool proj',
        base_price=15.00,
        price_per_page=20.00,
        unit='per page',
        project_type_id=14, 
        subject_id=14
    ),
        Service(
        title='Lab Report',
        description='cool proj',
        base_price=15.00,
        price_per_page=15.00,
        unit='per page',
        project_type_id=15, 
        subject_id=2
    ),
        Service(
        title='Editing',
        description='cool proj',
        base_price=15.00,
        price_per_page=5.00,
        unit='per page',
        project_type_id=16, 
        subject_id=2
    ),
        Service(
        title='Proofreading',
        description='cool proj',
        base_price=15.00,
        price_per_page=5.00,
        unit='per page',
        project_type_id=17, 
        subject_id=6
    ),
        Service(
        title='Rewrite',
        description='cool proj',
        base_price=2.00,
        price_per_page=7.00,
        unit='per page',
        project_type_id=18, 
        subject_id=1
    )

]


    # Create services with pricing per page
    # services = [
    #     Service(title='Essays',price=10.00, unit='per page', project_type=project_types[0], subject_id=1),
    #     Service(title='Admissions Essay', price=15.00, unit='per page', project_type=project_types[0], subject_id=2),
    #     Service(title='PowerPoint Presentation', price=8.00, unit='per slide', project_type=project_types[1], subject_id=3),
    #     Service(title='Research Paper', price=20.00, unit='per page', project_type=project_types[0], subject_id=1),
    #     Service(title='Assignments', price=12.00, unit='per page', project_type=project_types[0], subject_id=4),
    #     Service(title='Homework', price=12.00, unit='per page', project_type=project_types[0], subject_id=6),
    #     Service(title='Speech', price=10.00, unit='per page', project_type=project_types[0], subject_id=2),
    #     Service(title='Book Reviews', price=10.00, unit='per page', project_type=project_types[0], subject_id=8),
    #     Service(title='Coursework', price=15.00, unit='per page', project_type=project_types[0], subject_id=11),
    #     Service(title='Personal Statement', price=18.00, unit='per page', project_type=project_types[0], subject_id=3),
    #     Service(title='PhD Dissertation', price=30.00, unit='per page', project_type=project_types[0], subject_id=1),
    #     Service(title='Thesis', price=25.00, unit='per page', project_type=project_types[0], subject_id=4),
    #     Service(title='Case Study', price=22.00, unit='per page', project_type=project_types[1], subject_id=6),
    #     Service(title='Term Paper', price=15.00, unit='per page', project_type=project_types[0], subject_id=12),
    #     Service(title='Lab Report', price=20.00, unit='per page', project_type=project_types[1], subject_id=8),
    #     Service(title='Editing', price=5.00, unit='per page', project_type=project_types[0], subject_id=2),
    #     Service(title='Proofreading', price=4.00, unit='per page', project_type=project_types[0], subject_id=6),
    #     Service(title='Rewrite', price=7.00, unit='per page', project_type=project_types[0], subject_id=1),
    # ]

    # Create project requests
    # request1 = ProjectRequest(
    #     user_id=1,  # assuming user1 will get id=1
    #     expert_id=1,  # assuming expert1 will get id=1
    #     project_description='I need help with writing my research paper on literature review.',
    #     status='Pending'
    # )

    # request2 = ProjectRequest(
    #     user_id=1,  # assuming user1 will get id=1
    #     expert_id=2,  # assuming expert2 will get id=2
    #     project_description='Need a PowerPoint presentation on my engineering case study.',
    #     status='Pending'
    # )

    # Add users, experts, project types, services, and requests to the session
    db.session.add_all([user1, admin1, *project_types, expert1, expert2, *services])

    # Commit the session to the database
    db.session.commit()

# Drop and create all tables (be cautious, this will delete all data)
if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
        seed_database()
        print("Database seeded successfully!")
