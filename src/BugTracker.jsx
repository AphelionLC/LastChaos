import React, { useState } from 'react';
import { Trash2, CheckSquare, Square, X } from 'lucide-react';
import { Button } from './components/ui/button';
import { Card } from './components/ui/card';
import { Dialog } from './components/ui/dialog';
import { Select } from './components/ui/select';
import { Input } from './components/ui/input';
import { Textarea } from './components/ui/textarea';

const BugTracker = () => {
  const [issues, setIssues] = useState([
    { id: 1, title: "Login page crashes", description: "The login page crashes when...", category: "Server Side", status: "Open", completed: false },
    { id: 2, title: "Database connection error", description: "Unable to connect to the database...", category: "Server Side", status: "In Progress", completed: false },
    { id: 3, title: "Mobile app not responsive", description: "The mobile app is not responsive on...", category: "Client Side", status: "Open", completed: false },
    { id: 4, title: "Anticheat working", description: "there is no bug haha", category: "Client Side", status: "Closed", completed: true },
  ]);
  const [categories, setCategories] = useState(["Server Side", "Client Side"]);
  const [selectedCategory, setSelectedCategory] = useState("All Categories");
  const [newIssue, setNewIssue] = useState({ title: '', description: '', category: '', status: 'Open', completed: false });
  const [isNewIssueModalOpen, setIsNewIssueModalOpen] = useState(false);
  const [isNewCategoryModalOpen, setIsNewCategoryModalOpen] = useState(false);
  const [newCategory, setNewCategory] = useState('');

  const addIssue = () => {
    setIssues([...issues, { ...newIssue, id: Date.now() }]);
    setNewIssue({ title: '', description: '', category: '', status: 'Open', completed: false });
    setIsNewIssueModalOpen(false);
  };

  const toggleIssueCompletion = (id) => {
    setIssues(issues.map(issue => 
      issue.id === id ? { ...issue, completed: !issue.completed } : issue
    ));
  };

  const deleteIssue = (id) => {
    setIssues(issues.filter(issue => issue.id !== id));
  };

  const addCategory = () => {
    if (newCategory && !categories.includes(newCategory)) {
      setCategories([...categories, newCategory]);
      setNewCategory('');
      setIsNewCategoryModalOpen(false);
    }
  };

  const removeCategory = (categoryToRemove) => {
    setCategories(categories.filter(category => category !== categoryToRemove));
    setIssues(issues.map(issue => 
      issue.category === categoryToRemove ? { ...issue, category: 'Uncategorized' } : issue
    ));
    if (selectedCategory === categoryToRemove) {
      setSelectedCategory("All Categories");
    }
  };

  const getCardColor = (status) => {
    switch(status) {
      case 'Open': return 'bg-yellow-200';
      case 'In Progress': return 'bg-blue-200';
      case 'Closed': return 'bg-green-200';
      default: return 'bg-gray-200';
    }
  };
  
  const clearCompletedIssues = () => {
    setIssues(issues.filter(issue => !issue.completed));
  };

  return (
    <div className="flex h-screen bg-gray-900 text-white">
      <div className="w-1/4 p-4 border-r border-gray-700">
        <h1 className="text-2xl font-bold mb-4">My Bug Tracker</h1>
        <Button 
          className="w-full justify-start mb-2 bg-indigo-600 hover:bg-indigo-700"
          onClick={() => setSelectedCategory("All Categories")}
        >
          All Categories
        </Button>
        {categories.map(category => (
          <div key={category} className="flex items-center mb-2">
            <Button 
              className="flex-grow justify-start"
              onClick={() => setSelectedCategory(category)}
            >
              {category}
            </Button>
            <Button onClick={() => removeCategory(category)}>
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        ))}
        <Button onClick={() => setIsNewCategoryModalOpen(true)} className="w-full mt-2">Add Category</Button>
        
        <div className="mt-8">
          <h2 className="text-xl font-semibold mb-2">Fixed/Completed</h2>
          {issues.filter(issue => issue.completed).map(issue => (
            <div key={issue.id} className="flex items-center mb-2">
              <CheckSquare size={16} className="mr-2" />
              <span className="line-through text-sm truncate">{issue.title}</span>
            </div>
          ))}
        </div>
      </div>
      
      <div className="flex-1 p-4">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-2xl font-bold">{selectedCategory}</h2>
          <Button onClick={() => setIsNewIssueModalOpen(true)}>New Issue</Button>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {issues
            .filter(issue => !issue.completed && (selectedCategory === "All Categories" || issue.category === selectedCategory))
            .map(issue => (
            <Card key={issue.id} className={`${getCardColor(issue.status)} text-gray-900`}>
              <div className="p-4">
                <h3 className="font-bold mb-2">{issue.title}</h3>
                <p className="text-sm mb-2">{issue.description}</p>
                <div className="flex justify-between items-center">
                  <span className="text-xs">{issue.category}</span>
                  <div>
                    <Button onClick={() => toggleIssueCompletion(issue.id)}>
                      <Square size={16} />
                    </Button>
                    <Button onClick={() => deleteIssue(issue.id)}>
                      <Trash2 size={16} />
                    </Button>
                  </div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      </div>

      <Dialog open={isNewIssueModalOpen} onOpenChange={setIsNewIssueModalOpen}>
        <Dialog.Content>
          <Dialog.Header>
            <Dialog.Title>Create New Issue</Dialog.Title>
          </Dialog.Header>
          <div className="grid gap-4 py-4">
            <Input
              placeholder="Issue Title"
              value={newIssue.title}
              onChange={(e) => setNewIssue({ ...newIssue, title: e.target.value })}
            />
            <Textarea
              placeholder="Describe the bug..."
              value={newIssue.description}
              onChange={(e) => setNewIssue({ ...newIssue, description: e.target.value })}
            />
            <Select 
              onValueChange={(value) => setNewIssue({ ...newIssue, category: value })}
              options={categories.map(category => ({ value: category, label: category }))}
              placeholder="Select Category"
            />
            <Select
              onValueChange={(value) => setNewIssue({ ...newIssue, status: value })}
              options={[
                { value: 'Open', label: 'Open' },
                { value: 'In Progress', label: 'In Progress' },
                { value: 'Closed', label: 'Closed' }
              ]}
              placeholder="Select Status"
            />
          </div>
          <Dialog.Footer>
            <Button onClick={() => setIsNewIssueModalOpen(false)}>Cancel</Button>
            <Button onClick={addIssue}>Create Issue</Button>
          </Dialog.Footer>
        </Dialog.Content>
      </Dialog>

      <Dialog open={isNewCategoryModalOpen} onOpenChange={setIsNewCategoryModalOpen}>
        <Dialog.Content>
          <Dialog.Header>
            <Dialog.Title>Add New Category</Dialog.Title>
          </Dialog.Header>
          <div className="py-4">
            <Input
              placeholder="Category Name"
              value={newCategory}
              onChange={(e) => setNewCategory(e.target.value)}
            />
          </div>
          <Dialog.Footer>
            <Button onClick={() => setIsNewCategoryModalOpen(false)}>Cancel</Button>
            <Button onClick={addCategory}>Add Category</Button>
          </Dialog.Footer>
        </Dialog.Content>
      </Dialog>
    </div>
  );
};

export default BugTracker;